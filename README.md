# noer22

`noer22` is a Rust archiver focused on secure backups: compression + authenticated encryption in a single `.noer` file.

## What it does

- Packs files/folders into a single archive with `zstd` compression.
- Encrypts metadata and payload with AEAD (`ChaCha20-Poly1305` or `AES-256-GCM`).
- Derives keys with `Argon2id` (bounded and validated parameters).
- Supports password, keyfile, hybrid auth, and `age` recipient mode.
- Supports incremental/delta archives with deletion tombstones.
- Supports external checksum sidecars (`sha256` / `blake3`).
- Includes CLI + TUI wizard + optional desktop GUI.

## Installation

### From source

```bash
cargo build --release
```

Binary location:
- Windows: `target\\release\\noer22.exe`
- Linux/macOS: `target/release/noer22`

### Optional GUI binary

```bash
cargo build --release --features gui --bin noer22_gui
```

## CLI Overview

```bash
noer22 pack <input...> -o <output.noer> [-p <password>] [--keyfile <file>] \
  [--age-recipient AGE1...] \
  [-l <level>] [--cipher chacha|aes] [--incremental-index <index.json>] \
  [--checksum sha256|blake3] [--checksum-output <file>] \
  [--parallel-crypto] [--threads <n>]

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
- `pack` requires one auth family:
  - password/keyfile (`-p` and/or `--keyfile`), or
  - `--age-recipient`.
- `pack` default compression level is `8`.
- age-protected archives require `--age-identity` for `unpack`, `list`, and `verify`.
- `verify` supports checksum-only mode (no password) when `--checksum-file` is provided.

## Quick Examples

```bash
# Password archive
noer22 pack ./folder -o backup.noer -p "my_password"

# Hybrid auth (password + keyfile)
noer22 pack ./docs -o docs.noer -p "passphrase" --keyfile ./offline.key

# Keyfile-only
noer22 pack ./vault -o vault.noer --keyfile ./offline.key

# age recipient mode
noer22 pack ./vault -o vault-age.noer --age-recipient age1example...

# Unpack age archive
noer22 unpack vault-age.noer --age-identity ./identity.txt -C ./out

# Incremental archive
noer22 pack ./home -o home-delta.noer -p "secret" --incremental-index ./home-index.json

# Generate checksum sidecar
noer22 pack ./data -o data.noer -p "secret" --checksum blake3

# Verify only by sidecar
noer22 verify data.noer --checksum-file data.noer.blake3
```

## TUI Wizard

Run:

```bash
noer22 wizard
```

Includes:
- modes: pack/unpack/list/verify (`F1`..`F4`)
- in-place editable fields (`Tab`, arrows)
- `Enter` to execute
- auth/checksum/incremental controls

## Desktop GUI (optional)

Run:

```bash
cargo run --release --features gui --bin noer22_gui
```

Modes:
- `Pack`
- `Extract`
- `List`
- `Verify`

GUI supports:
- password + confirmation
- keyfile-only and password+keyfile
- age recipients (`Pack`)
- age identities (`Extract/List/Verify`)
- checksum sidecar workflows
- optional incremental index and `parallel-crypto`

## Benchmarking

Run the benchmark runner:

```bash
cargo run --release --bin noer22_bench -- \
  --input ./your_dataset \
  --rounds 5 \
  --warmup-rounds 1 \
  --sample-ms 20
```

Without `--input`, a synthetic mixed dataset is generated automatically.
If `7z`/`7zz` or `rar` are found, comparison rows are included.

Outputs:
- `bench_run_<timestamp>/benchmark_results.json`
- `bench_run_<timestamp>/benchmark_results.md`

See `BENCHMARK.md` for a sample snapshot and interpretation notes.

## `.noer` Format (Summary)

- Header (`64` bytes)
  - Magic: `NOER22\0\0`
  - Version: `1`
  - Compression: `0 = zstd`
  - Crypto: `0 = ChaCha20-Poly1305`, `1 = AES-256-GCM`
  - Salt (`16` bytes)
  - Nonce base (`12` bytes)
  - Argon2id params (`mem_kib`, `iters`, `parallelism`)
  - Flags (`keyfile_required`, `incremental_archive`, `age_recipients`)
- Optional age envelope (`u32 len + encrypted 32-byte file key`)
- Encrypted metadata chunk (`postcard` serialized)
- Compressed+encrypted payload chunks (`u32 len + ciphertext+tag`)

## Security and Guarantees

- Archive content is authenticated end-to-end.
- Header, flags, reserved bytes, KDF ranges, and chunk lengths are validated.
- `pack` writes atomically and refuses silent overwrite.
- `unpack` pre-authenticates payload before restore and avoids silent overwrite conflicts.

See full details in `SECURITY.md`.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit
```

CI (GitHub Actions) runs format, clippy, tests, and audit on Linux/Windows.

## Release Files

- `CHANGELOG.md`
- `RELEASE_NOTES.md`
- `SECURITY.md`
- `BENCHMARK.md`

## Screenshots

- `assets/screenshots/gui-pack.png`
- `assets/screenshots/gui-extract.png`
- `assets/screenshots/gui-list.png`
- `assets/screenshots/gui-verify.png`

## License

This project uses a custom personal-use-only license.
See `LICENSE` for terms.
