# SDK Integration Guide

This document explains how to integrate the SDK artifacts into your existing Citadel crate.

## Files Created

```
citadel-sdk/
├── sdk.rs              # Clean public API (add to src/)
├── cli.rs              # CLI binary (add to src/bin/citadel.rs)
├── lib_updated.rs      # Updated lib.rs exposing only SDK interface
├── Cargo_updated.toml  # Updated Cargo.toml with CLI binary
├── README.md           # Sellable README for GitHub/crates.io
├── SECURITY.md         # Expanded security policy with support info
├── SUPPORT.md          # Commercial support tiers
├── API_FREEZE.md       # Stability contract (critical for trust)
└── OPEN_CORE_DECISION.md  # Business model recommendation
```

## Integration Steps

### 1. Add the SDK module

```bash
# From your R_Citadel directory:
cp sdk.rs src/sdk.rs
```

### 2. Update lib.rs

Either:
- Replace `src/lib.rs` with `lib_updated.rs`, OR
- Add to your existing lib.rs:

```rust
// At the top of lib.rs
mod sdk;

// Re-export the clean SDK interface
pub use sdk::{Citadel, Aad, Context, SealError, OpenError, ...};
```

### 3. Add the CLI binary

```bash
mkdir -p src/bin
cp cli.rs src/bin/citadel.rs
```

### 4. Update Cargo.toml

Add the `[[bin]]` section and features from `Cargo_updated.toml`:

```toml
[[bin]]
name = "citadel"
path = "src/bin/citadel.rs"
required-features = ["cli"]

[features]
default = []
std = []
cli = ["std"]
```

### 5. Replace documentation files

```bash
cp README.md README.md
cp SECURITY.md SECURITY.md
cp SUPPORT.md SUPPORT.md
cp API_FREEZE.md API_FREEZE.md
```

### 6. Test the integration

```bash
# Run existing tests
cargo test

# Build CLI
cargo build --features cli

# Test CLI
./target/debug/citadel --help
./target/debug/citadel keygen --output /tmp/keys
./target/debug/citadel seal --key /tmp/keys/public.key \
    --aad "test" --context "test" \
    --input secret.txt --output secret.enc
./target/debug/citadel inspect secret.enc
```

## What Changes for Existing Code

### Breaking Changes (Minor)

The SDK introduces typed `Aad` and `Context` wrappers. Existing code using raw bytes:

```rust
// Before
citadel.encrypt(&pk, b"data", b"aad", b"ctx")?;

// After
citadel.seal(&pk, b"data", &Aad::raw(b"aad"), &Context::raw(b"ctx"))?;
```

### Backward Compatibility

The old `CitadelMlKem768` type is still available but deprecated:

```rust
#[deprecated(since = "0.1.0", note = "use Citadel instead")]
pub type CitadelMlKem768 = ...;
```

Existing code will compile with warnings.

## Publishing to crates.io

### Pre-flight checklist

```bash
# 1. Run all tests
cargo test --all-features

# 2. Check docs build
cargo doc --no-deps

# 3. Check package
cargo package --list

# 4. Dry run publish
cargo publish --dry-run
```

### Publish

```bash
cargo publish
```

### Post-publish

1. Tag the release: `git tag v0.1.0 && git push --tags`
2. Create GitHub release with changelog
3. Announce on relevant channels

## Next Steps

1. **Fill in placeholders** — Replace `[your-email]`, `[sales-email]`, etc.
2. **Add LICENSE files** — Create `LICENSE-MIT` and `LICENSE-APACHE`
3. **Create GitHub repo** — `mrcord77/rust_citadel`
4. **Set up CI** — GitHub Actions for tests + cargo audit
5. **Write CHANGELOG.md** — Document the 0.1.0 release

## Questions?

The SDK is designed to be a drop-in addition. Your existing tests should pass unchanged once the module paths are updated.

If you hit issues, the most common problems are:
- Missing `use` statements for the new types
- Feature flags not enabled for CLI
- Path mismatches in Cargo.toml
