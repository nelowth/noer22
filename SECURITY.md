# Security Notes

This document summarizes security-relevant design decisions and operational guardrails of `noer22`.

## Scope and Threat Model

`noer22` is designed to:
- provide confidentiality and integrity for archive metadata and payload
- detect tampering, truncation, and authentication failures
- avoid silent destructive writes during pack/unpack flows

`noer22` is not a substitute for:
- host compromise protection (malware on source/target machine)
- key management infrastructure
- external security review for high-stakes deployments

## Cryptography

### AEAD
- Metadata and payload use AEAD (`ChaCha20-Poly1305` or `AES-256-GCM`).
- AAD includes full serialized header bytes.
- Any ciphertext/tag corruption fails authentication.

### Nonces
- Header stores a 12-byte nonce base.
- Metadata uses chunk index `0`; payload starts at `1`.
- Counter overflow is rejected.

### KDF
- Key derivation uses Argon2id with per-archive random 16-byte salt.
- Accepted ranges:
  - memory: `64..=1024 MiB`
  - iterations: `3..=12`
  - parallelism: `1..=64`
- Untrusted header KDF values are validated against the same bounds.

### Auth Material
- Supports password-only, keyfile-only, password+keyfile, and age recipient mode.
- For recipient mode, archive stores an age-wrapped file key envelope.

## Format Hardening

- Versioned header (`VERSION`).
- Unknown flags are rejected.
- Non-zero reserved header bytes are rejected.
- Invalid/corrupt chunk lengths are rejected with explicit upper bounds.
- No implicit fallback to default KDF values on malformed headers.

## IO Safety

### Pack
- Writes archive via temp file + atomic persist/rename.
- Refuses to overwrite existing output archive silently.

### Unpack
- Pre-authenticates full payload before restoration.
- Refuses silent overwrite conflicts in full restore mode.
- Uses temp+persist semantics for file output.

## Integrity and Failure Behavior

Expected failure class for cryptographic mismatch/tamper:
- authentication failure (`wrong password or corrupted archive`)

Practical implication:
- corrupted, truncated, or modified archives should not verify/decrypt successfully.

## Validation Coverage

Automated coverage includes:
- tamper/truncation rejection
- wrong-password failures
- keyfile-only and age-recipient workflows
- incremental tombstones and restore behavior
- many-small-files and unusual path cases
- overwrite refusal behavior

## CI Quality Gates

GitHub CI runs:
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo audit`

## Residual Considerations

- Payload pre-authentication in unpack trades speed for safety.
- For very large archives, validate runtime/memory profile in your deployment environment.
- Independent external review is recommended before high-stakes production use.
