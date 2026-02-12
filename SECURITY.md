# Security Notes

This document describes the security-relevant design and guardrails of `noer22`.

## 1) Cryptography

### AEAD usage
- Payload and metadata are encrypted with AEAD (`ChaCha20-Poly1305` or `AES-256-GCM`).
- The authenticated data (AAD) includes the full serialized archive header bytes.
- Any ciphertext/tag corruption fails decryption with `AuthenticationFailed`.

### Nonce strategy
- Each archive stores a 12-byte nonce base in the header.
- The first 8 bytes are random per archive.
- The last 4 bytes are a counter prefix (starting at `0`).
- Chunk nonces are derived as `nonce_base_prefix || counter+chunk_index`.
- Metadata uses chunk index `0`; payload starts at `1`.
- Counter overflow is rejected.

### KDF (Argon2id)
- Key derivation uses Argon2id with per-archive random 16-byte salt.
- Pack-time KDF ranges are enforced:
  - memory: `64..=1024 MiB`
  - iterations: `3..=12`
  - parallelism: `1..=64`
- Header KDF values from untrusted archives are validated against the same bounds.

### No insecure fallback
- There is no plaintext mode and no automatic downgrade path.
- Header parsing no longer falls back to implicit/default KDF values when fields are invalid.

## 2) Archive format hardening

- Header is versioned (`VERSION` field).
- Unknown header flags are rejected.
- Non-zero reserved header bytes are rejected.
- Invalid/corrupt chunk lengths are rejected with explicit safety limits.

## 3) Failure safety and IO behavior

### Packing
- Output archive write is atomic:
  - write to temp file in destination directory
  - persist/rename only after successful completion
- Existing output archive is not overwritten silently.

### Unpacking
- Payload is fully authenticated in a preflight pass before writing output files.
- Full restore mode refuses to overwrite existing conflicting paths.
- File extraction uses temporary files + atomic persist per file.
- On extraction failure, an explicit message indicates possible partial output.

## 4) Edge-case handling

The test suite covers:
- corruption/tamper/truncation rejection,
- keyfile-only and age-recipient workflows,
- incremental tombstones and restore behavior,
- many small files, empty files, and unusual file names,
- overwrite refusal in full restore mode.

## 5) Operational quality gates

- CI runs on Linux and Windows with:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -D warnings`
  - `cargo test --all-features`
  - `cargo audit`

## 6) Remaining considerations

- Preflight payload authentication in unpack favors safety over speed (double read/decrypt pass).
- For extremely large archives/datasets, validate operational limits in your target environment.
- External independent review is still recommended before high-stakes production use.
