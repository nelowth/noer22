# Release Notes (GitHub-ready)

## noer22 v0.3.1 (2026-02-12)

Maintenance and hardening release focused on reliability, documentation quality, and release hygiene.

### Highlights

- Removed panic-prone `unwrap`/`expect` paths from production runtime flows.
- Hardened GUI shared state handling against poisoned mutexes.
- Updated `Cargo.lock` to latest compatible dependency versions.
- Added `.gitignore` for build, benchmark, and local archive/checksum outputs.
- Improved CI efficiency:
  - workflow concurrency cancellation
  - `cargo-audit` install via `taiki-e/install-action`
- Performed complete documentation refresh (`README`, `SECURITY`, `BENCHMARK`, screenshot guide).
- Aligned crate version and release docs to `0.3.1`.

### Validation Executed

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo audit`

All checks passed.

## noer22 v0.3.0

Feature release focused on practical backup workflows: keyfile auth, age public-key mode, incremental/delta mode, and checksum-driven verification.

### Highlights

- Keyfile support (`--keyfile`) for pack/unpack/list/verify.
- Hybrid auth (`password + keyfile`) and keyfile-only archives.
- age recipient mode (`--age-recipient`) and identity-based decryption (`--age-identity`).
- GUI auth parity (password/keyfile + age), checksum workflows, incremental index selection, and parallel-crypto toggle.
- `noer22_bench` binary with multi-round statistics and resource sampling.
- Strict hardening:
  - strict header validation
  - bounded chunk-length checks
  - atomic archive writing and overwrite refusal
  - payload pre-authentication before extraction
- Incremental/delta mode with BLAKE3 fingerprints.
- Incremental tombstones for removed files.
- External checksum generation and verification.
- Checksum-only verify flow (`verify --checksum-file ...`).
- Full-screen terminal wizard (`ratatui`) for pack/unpack/list/verify.

### Commands

```bash
noer22 pack <input...> -o backup.noer [-p PASS] [--keyfile FILE] \
  [--age-recipient AGE1...] [--incremental-index index.json] \
  [--checksum sha256|blake3] [--parallel-crypto]

noer22 unpack backup.noer --age-identity identity.txt -C out

noer22 verify backup.noer --checksum-file backup.noer.sha256
```
