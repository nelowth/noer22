# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - 2026-02-11

### Added
- New CLI command `list` to inspect `.noer` contents without extraction.
- New CLI command `verify` to validate password and full archive integrity.
- New GUI modes: `List` and `Verify`.
- In-app archive index view in GUI list mode (entries, counts, payload size, crypto/KDF summary).
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
- Hardened archive metadata path checks using conflict-aware relative path validation.
- Improved error handling for malformed/truncated archives and auth failures.

### Tests
- Added/updated integration coverage for:
  - roundtrip pack/unpack,
  - wrong-password failures,
  - `list` and `verify` flows,
  - empty root directory preservation.

### Docs
- Added release-ready notes in `RELEASE_NOTES.md`.
- Added showcase guidance and screenshot template section in `README.md`.
