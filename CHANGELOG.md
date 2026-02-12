# Changelog

All notable changes to this project are documented in this file.

## [0.3.1] - 2026-02-12

### Changed
- Updated dependency lockfile (`Cargo.lock`) to latest compatible crate versions (`cargo update`).
- Aligned crate version in `Cargo.toml` with release history (`0.3.1`).
- Added repository `.gitignore` for build, benchmark, and local archive/checksum artifacts.
- CI now uses workflow concurrency cancellation to reduce duplicate runs.
- CI audit job now installs `cargo-audit` via `taiki-e/install-action` for faster setup.
- Refreshed project documentation (`README.md`, `SECURITY.md`, `BENCHMARK.md`, screenshot guide).

### Fixed
- Removed panic-prone `unwrap`/`expect` paths from production code in header parsing, TUI field editing, and GUI shared-state locking.
- GUI status and archive inspection state now recover safely from poisoned mutexes instead of panicking.
- Progress bar style setup now falls back safely when template parsing fails.

## [0.3.0] - 2026-02-11

### Added
- Optional keyfile authentication for `pack`, `unpack`, `list`, and `verify` (`--keyfile`).
- Hybrid auth support (`password + keyfile`) and keyfile-only mode.
- Optional public-key mode with age recipients (`--age-recipient`) and identities (`--age-identity`).
- Incremental/delta packing via `--incremental-index <file>` using per-file BLAKE3 fingerprints.
- Incremental deletion tombstones for removed files (applied during `unpack`).
- External checksum sidecars during pack (`--checksum sha256|blake3`).
- Checksum-only verify mode (`verify --checksum-file ...`) without password.
- Optional pre-extract checksum validation in `unpack`.
- New full-screen `ratatui` wizard (`noer22 wizard`) with pack/unpack/list/verify forms.
- New modules: `checksum` and `incremental`.

### Changed
- Archive header now stores feature flags (`keyfile_required`, `incremental_archive`, `age_recipients`).
- `list` output now reports auth mode and archive mode (full/incremental).
- `list` output now includes deletion entries (`[DEL]`) for incremental archives.
- CLI auth model updated from password-only to password-or-keyfile where applicable.
- Added `--parallel-crypto` experimental deterministic parallel chunk encryption path.
- `pack` default compression level updated from `6` to `8`.
- GUI now supports both auth families end-to-end (password/keyfile and age).
- GUI now exposes checksum-sidecar workflows and incremental/parallel controls.
- Added `noer22_bench` binary for reproducible benchmark runs.
- Benchmark runner now supports multi-round stats + peak RAM/CPU sampling.
- Header validation is strict: rejects unknown flags, non-zero reserved bytes, invalid/implicit KDF values.
- Archive decoder now enforces safe maximum chunk size bounds.
- `pack` uses atomic output writes and refuses silent overwrite.
- `unpack` performs full payload pre-authentication before extraction and uses temp+persist writes.
- Full restore mode refuses silent overwrite conflicts.

### Security
- Key derivation supports combined password and keyfile material.
- Added age-wrapped file-key envelope for recipient-based archives.
- Keyfile-protected archives fail early when keyfile is missing.
- Sidecar verification supports explicit algorithm matching.
- Added `SECURITY.md` with cryptographic and safety notes.

### Performance
- Incremental hashing pipeline is parallelized with Rayon.
- Multi-threaded zstd path remains available via `--threads`.

### Tests
- Added integration coverage for keyfile-only roundtrip and missing-keyfile failure.
- Added checksum-sidecar verify without password coverage.
- Added incremental mode changed-files-only coverage.

## [0.2.0] - 2026-02-11

### Added
- New CLI command `list` to inspect `.noer` contents without extraction.
- New CLI command `verify` to validate password and full archive integrity.
- New GUI modes: `List` and `Verify`.
- In-app archive index view in GUI list mode.
- New backend API `inspect_archive()` returning structured archive overview.

### Changed
- Full UX text pass to professional English across CLI, Wizard (TUI), GUI, and docs.
- README rewritten for publication quality with clearer onboarding and feature positioning.
- Project licensing switched to a custom personal-use-only license.

### Fixed
- Path mapping and collision handling in `pack` for repeated root names.
- Root-directory preservation in archives, including empty input roots.
- Safer metadata path validation during `unpack` to block path conflicts.
- Buffered encryption writer flush behavior to avoid pending-data edge cases.

### Performance
- Reduced allocation pressure in crypto chunk pipeline.
- Streamlined chunk encryption/decryption buffer reuse.

### Security
- Hardened archive metadata path checks with conflict-aware relative path validation.
- Improved error handling for malformed/truncated archives and auth failures.

### Tests
- Added/updated integration coverage for roundtrip pack/unpack.
- Added wrong-password failure coverage.
- Added `list` and `verify` flow coverage.
- Added empty root directory preservation coverage.
