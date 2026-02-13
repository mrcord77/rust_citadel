# Drop-In Fixes

Copy these files over your project tree. All paths are relative to repo root.

## What's Fixed

| Issue | Severity | File(s) |
|-------|----------|---------|
| Doctest fails (`citadel_sdk` → `citadel_envelope`, `?` → `.unwrap()`) | **Error** | `src/sdk.rs` |
| Unused import `alloc::string::String` | Warning | `src/sdk.rs` |
| Unused import `Duration` | Warning | `benches/timing.rs` |
| 8× deprecated `CitadelMlKem768`/`CitadelHybrid` alias usage | Warning | all other files |

## Files (8)

```
src/sdk.rs                        # doctest fix + removed unused String import
src/bin/citadel.rs                # CitadelMlKem768 → Citadel + Aad/Context
tests/kat.rs                      # CitadelMlKem768 → Citadel + Aad/Context
tests/roundtrip.rs                # CitadelMlKem768 → Citadel + Aad/Context
benches/timing.rs                 # removed Duration, CitadelMlKem768 → Citadel
benches/comparative.rs            # CitadelHybrid → Citadel + Aad/Context
examples/demo.rs                  # CitadelHybrid → Citadel + Aad/Context
fuzz/fuzz_targets/decrypt_full.rs # CitadelMlKem768 → Citadel + Aad/Context
```

## Apply

```bash
cp -r src/ tests/ benches/ examples/ fuzz/ /path/to/R_Citadel/
```

## Expected Result

- `cargo test` → 22/22 tests pass + **doctest passes** (was failing)
- `cargo build` → **zero warnings** (was 10)
