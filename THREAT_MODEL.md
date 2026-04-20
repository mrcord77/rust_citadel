# Threat Model

## What this project is
A misuse-resistant hybrid encryption envelope intended for sealed blobs/artifacts and store-and-forward encryption.

## Security goals
- Confidentiality and integrity of the plaintext under an active attacker who can modify ciphertexts.
- Resistance to common misuse: wrong key, wrong AAD, wrong context, truncated/malformed inputs.
- Hybrid security: security holds if *either* X25519 or ML-KEM-768 remains secure. Both shared secrets are combined in the KDF; an attacker must break both primitives to recover plaintext.

## Non-goals
- Key management, access control, identity, or authentication.
- Replacing TLS/HPKE for interactive transport protocols.
- Claiming FIPS validation or compliance certification.

## Attacker model
- Can observe ciphertexts and attempt arbitrary modifications.
- Can feed chosen ciphertexts to the decryptor and observe success/failure.
- May attempt downgrade and format-confusion attacks.
- May attempt resource-exhaustion with oversized inputs.

## Notes on side channels
This project aims to avoid obvious timing/error oracles at the protocol layer, but does not claim constant-time behavior for all code paths on all platforms. Constant-time properties are inherited from dependencies (`x25519-dalek`, `ml-kem`, `aes-gcm`, `subtle`) and have not been independently verified.
