//! Citadel CLI — operational tooling for encryption/decryption
//!
//! Usage:
//!   citadel keygen --output <dir>
//!   citadel seal --key <pk_file> --aad <aad> --context <ctx> --input <file> --output <file>
//!   citadel open --key <sk_file> --aad <aad> --context <ctx> --input <file> --output <file>
//!   citadel inspect <file>

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use citadel_envelope::{CitadelMlKem768, PublicKey, SecretKey};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }

    let result = match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "seal" => cmd_seal(&args[2..]),
        "open" => cmd_open(&args[2..]),
        "inspect" => cmd_inspect(&args[2..]),
        "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "--version" | "-V" => {
            println!("citadel {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        cmd => {
            eprintln!("error: unknown command '{}'", cmd);
            print_usage();
            Err("unknown command".into())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        r#"Citadel CLI — hybrid post-quantum encryption

USAGE:
    citadel <COMMAND> [OPTIONS]

COMMANDS:
    keygen      Generate a new keypair
    seal        Encrypt a file
    open        Decrypt a file
    inspect     Show ciphertext metadata (no decryption)

EXAMPLES:
    # Generate keypair
    citadel keygen --output ./keys

    # Encrypt
    citadel seal \
        --key ./keys/public.key \
        --aad "backup|db|2026" \
        --context "myapp|prod" \
        --input secret.txt \
        --output secret.enc

    # Decrypt
    citadel open \
        --key ./keys/secret.key \
        --aad "backup|db|2026" \
        --context "myapp|prod" \
        --input secret.enc \
        --output secret.txt

    # Inspect
    citadel inspect secret.enc

OPTIONS:
    -h, --help       Print help
    -V, --version    Print version
"#
    );
}

fn cmd_keygen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut output_dir = PathBuf::from(".");
    
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                output_dir = PathBuf::from(args.get(i).ok_or("missing output path")?);
            }
            _ => return Err(format!("unknown option: {}", args[i]).into()),
        }
        i += 1;
    }

    fs::create_dir_all(&output_dir)?;

    let citadel = CitadelMlKem768::new();
    let (pk, sk) = citadel.keygen();

    let pk_path = output_dir.join("public.key");
    let sk_path = output_dir.join("secret.key");

    fs::write(&pk_path, pk.to_bytes())?;
    fs::write(&sk_path, sk.to_bytes())?;

    // Restrict secret key permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&sk_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&sk_path, perms)?;
    }

    eprintln!("Generated keypair:");
    eprintln!("  Public key:  {}", pk_path.display());
    eprintln!("  Secret key:  {} (mode 600)", sk_path.display());
    eprintln!();
    eprintln!("Public key size:  {} bytes", pk.to_bytes().len());
    eprintln!("Secret key size:  {} bytes", sk.to_bytes().len());

    Ok(())
}

fn cmd_seal(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut key_path: Option<PathBuf> = None;
    let mut aad = String::new();
    let mut context = String::new();
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" | "-k" => {
                i += 1;
                key_path = Some(PathBuf::from(args.get(i).ok_or("missing key path")?));
            }
            "--aad" | "-a" => {
                i += 1;
                aad = args.get(i).ok_or("missing aad")?.clone();
            }
            "--context" | "-c" => {
                i += 1;
                context = args.get(i).ok_or("missing context")?.clone();
            }
            "--input" | "-i" => {
                i += 1;
                input_path = Some(PathBuf::from(args.get(i).ok_or("missing input path")?));
            }
            "--output" | "-o" => {
                i += 1;
                output_path = Some(PathBuf::from(args.get(i).ok_or("missing output path")?));
            }
            _ => return Err(format!("unknown option: {}", args[i]).into()),
        }
        i += 1;
    }

    let key_path = key_path.ok_or("missing --key")?;
    let output_path = output_path.ok_or("missing --output")?;

    // Load public key
    let pk_bytes = fs::read(&key_path)?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| "invalid public key")?;

    // Read plaintext
    let plaintext = if let Some(ref path) = input_path {
        fs::read(path)?
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    // Encrypt
    let citadel = CitadelMlKem768::new();
    let ciphertext = citadel
        .encrypt(&pk, &plaintext, aad.as_bytes(), context.as_bytes())
        .map_err(|_| "encryption failed")?;

    // Write ciphertext
    fs::write(&output_path, &ciphertext)?;

    eprintln!("Encrypted {} bytes -> {} bytes", plaintext.len(), ciphertext.len());
    eprintln!("Output: {}", output_path.display());

    Ok(())
}

fn cmd_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut key_path: Option<PathBuf> = None;
    let mut aad = String::new();
    let mut context = String::new();
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" | "-k" => {
                i += 1;
                key_path = Some(PathBuf::from(args.get(i).ok_or("missing key path")?));
            }
            "--aad" | "-a" => {
                i += 1;
                aad = args.get(i).ok_or("missing aad")?.clone();
            }
            "--context" | "-c" => {
                i += 1;
                context = args.get(i).ok_or("missing context")?.clone();
            }
            "--input" | "-i" => {
                i += 1;
                input_path = Some(PathBuf::from(args.get(i).ok_or("missing input path")?));
            }
            "--output" | "-o" => {
                i += 1;
                output_path = Some(PathBuf::from(args.get(i).ok_or("missing output path")?));
            }
            _ => return Err(format!("unknown option: {}", args[i]).into()),
        }
        i += 1;
    }

    let key_path = key_path.ok_or("missing --key")?;

    // Load secret key
    let sk_bytes = fs::read(&key_path)?;
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| "invalid secret key")?;

    // Read ciphertext
    let ciphertext = if let Some(ref path) = input_path {
        fs::read(path)?
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    // Decrypt
    let citadel = CitadelMlKem768::new();
    let plaintext = citadel
        .decrypt(&sk, &ciphertext, aad.as_bytes(), context.as_bytes())
        .map_err(|_| "decryption failed")?;

    // Write plaintext
    if let Some(ref path) = output_path {
        fs::write(path, &plaintext)?;
        eprintln!("Decrypted {} bytes -> {} bytes", ciphertext.len(), plaintext.len());
        eprintln!("Output: {}", path.display());
    } else {
        io::stdout().write_all(&plaintext)?;
    }

    Ok(())
}

fn cmd_inspect(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = args.first().ok_or("missing file path")?;
    
    let ciphertext = fs::read(input_path)?;
    
    use citadel_envelope::wire::{
        decode_wire, MIN_CIPHERTEXT_BYTES, 
        SUITE_KEM_HYBRID_X25519_MLKEM768, SUITE_AEAD_AES256GCM,
    };

    let parts = decode_wire(&ciphertext).map_err(|_| "invalid ciphertext format")?;

    let kem_suite = if parts.suite_kem == SUITE_KEM_HYBRID_X25519_MLKEM768 {
        "X25519 + ML-KEM-768 (hybrid)"
    } else {
        "unknown"
    };

    let aead_suite = if parts.suite_aead == SUITE_AEAD_AES256GCM {
        "AES-256-GCM"
    } else {
        "unknown"
    };

    let plaintext_bytes = ciphertext.len().saturating_sub(MIN_CIPHERTEXT_BYTES);

    println!("Citadel Ciphertext");
    println!("==================");
    println!("Version:         {}", parts.version);
    println!("KEM Suite:       0x{:02X} ({})", parts.suite_kem, kem_suite);
    println!("AEAD Suite:      0x{:02X} ({})", parts.suite_aead, aead_suite);
    println!("Flags:           0x{:02X}", parts.flags);
    println!("KEM CT Length:   {} bytes", parts.kem_ct_len);
    println!();
    println!("Total Size:      {} bytes", ciphertext.len());
    println!("Overhead:        {} bytes", MIN_CIPHERTEXT_BYTES);
    println!("Plaintext Size:  ~{} bytes", plaintext_bytes);

    Ok(())
}
