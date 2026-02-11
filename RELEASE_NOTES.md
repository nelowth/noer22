# Release Notes (GitHub-ready)

## noer22 v0.3.0

A feature release focused on practical backup workflows: keyfile auth, age public-key mode, incremental/delta mode, and passwordless checksum verification.

### Highlights
- Added keyfile support (`--keyfile`) for pack/unpack/list/verify.
- Added hybrid auth (`password + keyfile`) and keyfile-only archives.
- Added age recipient mode (`--age-recipient`) and identity-based decryption (`--age-identity`).
- Desktop GUI now supports full auth parity (password/keyfile + age), checksum workflows,
  incremental index selection, and parallel-crypto toggle.
- Added `noer22_bench` benchmark binary to compare noer22 against optional `7z` on the same dataset.
- Updated `pack` default compression level to `8` (from `6`) based on mixed workload benchmark results.
- Added incremental/delta mode (`--incremental-index`) using BLAKE3 fingerprints.
- Added incremental tombstones for removed files (applied during unpack).
- Added external checksum generation (`--checksum sha256|blake3`) and verification.
- Added checksum-only verification flow (`verify --checksum-file ...`) without password.
- Added full-screen terminal wizard (`ratatui`) for pack/unpack/list/verify flows.
- Added `--parallel-crypto` experimental deterministic parallel encryption pipeline.

### What Changed

#### Core
- Extended archive header flags to indicate keyfile-protected, incremental, and age-recipient archives.
- Updated KDF input model to combine password + keyfile material when both are present.
- Added age-wrapped file-key envelope for recipient-based archives.
- Incremental archives now emit deletion tombstones for removed files.
- Added sidecar checksum module with strict algorithm handling.
- Added incremental index module (JSON) with parallel file hashing.

#### UX
- `list` now reports auth mode and archive mode (full/incremental).
- `unpack` can verify checksum sidecar before extraction.

#### Validation
- Added integration tests for:
  - keyfile-only roundtrip and missing-keyfile failure,
  - age recipient roundtrip using generated identity,
  - checksum-sidecar verification without password,
  - incremental archive containing only changed files.

### Commands
```bash
noer22 pack <input...> -o backup.noer [-p PASS] [--keyfile FILE] \
  [--age-recipient AGE1...] [--incremental-index index.json] \
  [--checksum sha256|blake3] [--parallel-crypto]

noer22 unpack backup.noer --age-identity identity.txt -C out

noer22 verify backup.noer --checksum-file backup.noer.sha256
```

### Validation Executed
- `cargo fmt`
- `cargo test`
- `cargo test --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`

All checks passed.

### Notes
- Incremental archives contain changed/new files only.
- Removed files are emitted as deletion tombstones and applied during unpack.
