# Release Notes (GitHub-ready)

## noer22 v0.2.0

A major quality and usability release focused on archive reliability, professional UX, and production-ready documentation.

### Highlights
- Added `list` and `verify` commands to the CLI.
- Added `List` and `Verify` modes to the desktop GUI.
- Improved pack/unpack reliability for tricky path structures.
- Reduced allocation overhead in the crypto chunk pipeline.
- Upgraded docs and release assets for GitHub publishing.

### What Changed

#### Core Improvements
- Fix path mapping/collision handling in pack to preserve root directories and support empty directory inputs.
- Optimize crypto chunk pipeline to reduce allocations and correct buffered flush semantics.
- Add new CLI commands list and verify with implementation modules.
- Harden unpack with metadata path validation and clearer error handling.

#### Tests and Docs
- Add/update tests and docs, then run full test suite.
- Updated README with clearer onboarding and GUI mode descriptions.
- Added changelog and this release-notes draft.

### Validation
- `cargo fmt`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`

All checks passed.

### GUI Showcase Template
Add screenshots to:
- `assets/screenshots/gui-pack.png`
- `assets/screenshots/gui-extract.png`
- `assets/screenshots/gui-list.png`
- `assets/screenshots/gui-verify.png`

### Notes on License
This release uses a custom personal-use-only license. Commercial distribution, resale, and monetized forks require prior written authorization.
