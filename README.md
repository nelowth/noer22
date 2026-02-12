# noer22

`noer22` is a Rust archive tool that packs files/folders into a single `.noer` file with:
- Zstd compression (multi-threaded)
- AEAD encryption (ChaCha20-Poly1305 or AES-256-GCM)
- Argon2id key derivation
- Optional keyfile support (password + keyfile or keyfile-only)
- Optional age recipient mode (public-key, `--age-recipient` / `--age-identity`)
- Optional incremental/delta mode via external JSON index
- Optional external checksum sidecars (`.sha256` / `.blake3`)
- Incremental deletion tombstones (removed files are applied on extraction)
- Full-screen terminal UI (`noer22 wizard`) built with `ratatui`

## Quick Start (CLI)

```bash
noer22 pack <input...> -o <output.noer> [-p <password>] [--keyfile <file>] \
  [--age-recipient AGE1...] \
  [-l <level>] [--cipher chacha|aes] [--incremental-index <index.json>] \
  [--checksum sha256|blake3] [--checksum-output <file>] [--parallel-crypto]

noer22 unpack <archive.noer> [-p <password>] [--keyfile <file>] \
  [--age-identity <identity.txt>] [-C <dir>] \
  [--checksum-file <file>] [--checksum-algo sha256|blake3]

noer22 list <archive.noer> [-p <password>] [--keyfile <file>] \
  [--age-identity <identity.txt>] [--long]

noer22 verify <archive.noer> [-p <password>] [--keyfile <file>] \
  [--age-identity <identity.txt>] \
  [--checksum-file <file>] [--checksum-algo sha256|blake3]

noer22 wizard
```

Rules:
- `pack` requires one auth mode: `(password and/or keyfile)` OR `age recipient(s)`.
- `pack` default compression level is `8` (tuned for better speed/ratio balance).
- `unpack`/`list`/`verify` for age archives require `--age-identity` files.
- `verify` accepts checksum-only mode (no password) when `--checksum-file` is provided.

## Examples

```bash
# Standard password archive
noer22 pack ./folder -o backup.noer -p "my_password" -l 10

# Hybrid auth (password + keyfile)
noer22 pack ./docs -o docs.noer -p "passphrase" --keyfile ./offline.key

# Keyfile-only archive
noer22 pack ./vault -o vault.noer --keyfile ./offline.key

# Public-key archive (age recipient)
noer22 pack ./vault -o vault-age.noer --age-recipient age1example...

# Extract public-key archive using identity file
noer22 unpack vault-age.noer --age-identity ./identity.txt -C ./out

# Incremental/delta backup (changed/new files only)
noer22 pack ./home -o home-delta.noer -p "secret" --incremental-index ./home-index.json

# Experimental deterministic parallel encryption path
noer22 pack ./big-data -o big.noer -p "secret" --parallel-crypto --threads 8

# Generate BLAKE3 sidecar
noer22 pack ./data -o data.noer -p "secret" --checksum blake3

# Verify using only sidecar checksum (no password)
noer22 verify data.noer --checksum-file data.noer.blake3

# Extract with keyfile and pre-check sidecar
noer22 unpack data.noer --keyfile ./offline.key -C ./out --checksum-file data.noer.blake3
```

## Interactive Wizard (TUI)

`noer22 wizard` launches a full-screen TUI:
- mode tabs for pack/unpack/list/verify (`F1`..`F4`)
- editable fields in-place (`Tab`, arrows, `Enter` to run)
- support for keyfile, age identities, checksum and incremental settings
- status panel with execution result

## Desktop GUI (optional)

Run the desktop app:

```bash
cargo run --release --features gui --bin noer22_gui
```

GUI modes:
- `Pack`: build encrypted archives
- `Extract`: unpack encrypted archives
- `List`: inspect archive contents without extraction
- `Verify`: validate full archive integrity

GUI auth options:
- Password + confirmation
- Keyfile-only or password+keyfile workflows (same as CLI)
- age recipients in `Pack` mode
- age identity files in `Extract`, `List`, and `Verify`

GUI usability updates:
- Input deduplication for dropped/selected pack sources
- `.noer` validation when selecting or dropping archive files
- Archive entry filter in `List` mode
- Suggested output paths based on selected inputs/archive location
- Checksum sidecar controls in `Pack`, optional checksum pre-check in `Extract`, and checksum-only verify in `Verify`
- Optional incremental index and parallel-crypto toggles in `Pack`

## Benchmarking

Run the built-in benchmark runner:

```bash
cargo run --release --bin noer22_bench -- \
  --input ./your_dataset \
  --rounds 5 \
  --warmup-rounds 1 \
  --sample-ms 20
```

Without `--input`, it generates a synthetic mixed dataset automatically.
If `7z`/`7zz` and/or `rar` are available, it also adds those comparison rows.
Outputs are written to `bench_run_<timestamp>/benchmark_results.{json,md}` by default.
The report includes mean/stddev (multi-round), ratio, peak RSS, and peak CPU for `pack`/`extract`.

## Showcase (template)

Short product-style description:
- **Pack** archives with compression + encryption in one flow.
- **Extract** safely with metadata-aware restoration.
- **List** archive contents before extraction.
- **Verify** full archive integrity end-to-end.

screenshots at these paths:
- `assets/screenshots/gui-pack.png`
- `assets/screenshots/gui-extract.png`
- `assets/screenshots/gui-list.png`
- `assets/screenshots/gui-verify.png`


```md
![Pack Mode](assets/screenshots/gui-pack.png)
*Pack mode: select inputs, output, cipher, and KDF settings.*

![Extract Mode](assets/screenshots/gui-extract.png)
*Extract mode: restore archive content to a chosen folder.*

![List Mode](assets/screenshots/gui-list.png)
*List mode: inspect entries and metadata without extracting files.*

![Verify Mode](assets/screenshots/gui-verify.png)
*Verify mode: validate password and full archive integrity.*
```

## Release Assets

- Changelog: `CHANGELOG.md`
- GitHub release notes draft: `RELEASE_NOTES.md`
- Security design notes: `SECURITY.md`

## `.noer` Format (summary)

- Header (64 bytes)
  - Magic: `NOER22\0\0`
  - Version: `1`
  - Compression: `0 = zstd`
  - Crypto: `0 = ChaCha20-Poly1305`, `1 = AES-256-GCM`
  - Salt (16 bytes)
  - Nonce base (12 bytes)
  - Argon2id params (`mem_kib`, `iters`, `parallelism`)
  - Flags (`keyfile_required`, `incremental_archive`, `age_recipients`)

- Optional age envelope (when `age_recipients` is set)
  - `u32` length + age-encrypted 32-byte file key

- Encrypted metadata (chunk 0)
  - Entries with relative path, size, timestamp, mode, directory flag, and deletion tombstone flag
  - Serialized with `postcard`

- Compressed + encrypted payload (sequential chunks)
  - Single zstd stream for all file data
  - Each chunk has authenticated tag and `u32` length prefix

## Notes

- All content is authenticated. Any tampering fails decryption.
- Streaming design supports large files.
- Empty directories are preserved, including input root directories.
- Incremental mode stores full file fingerprints in the index file; produced archives contain changed/new files only.
- Removed files are emitted as tombstone entries in incremental archives and are deleted on unpack.

## Development

```bash
cargo build --release
cargo build --release --features gui --bin noer22_gui
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
```

## License

This project uses a **custom personal-use-only license**.

Commercial use, resale, monetized redistribution, and monetized forks are not allowed without prior written authorization.
See `LICENSE` for full terms.

If you find improvements (features, performance, security, UX), please contact the author via repository issues/profile before publishing derivative distributions.
