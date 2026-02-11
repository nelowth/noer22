# Benchmark Snapshot

Date: 2026-02-11  
Host: Windows 11, PowerShell 5.1, NanaZip (`7z`) installed, `rar` binary not present in PATH.

Dataset (mixed):
- 96.31 MB total (`100,992,498` bytes)
- Highly compressible text block
- Incompressible random block
- Many small files
- Project `src/` + `README.md` snapshot

Measured commands:
- `noer22` pack/unpack with password auth
- `7z` pack/extract with encrypted headers (`-mhe=on -p...`)

| name | pack_ms | extract_ms | archive_bytes | ratio |
|---|---:|---:|---:|---:|
| noer22_l8 | 776.79 | 2535.48 | 50,654,805 | 0.5016 |
| noer22_l6 | 798.78 | 2506.11 | 50,657,256 | 0.5016 |
| noer22_l8_parallel | 843.92 | 2395.36 | 50,654,805 | 0.5016 |
| 7z_mx7 | 8202.36 | 9467.68 | 50,419,716 | 0.4992 |
| 7z_mx9 | 8725.04 | 17691.73 | 50,419,716 | 0.4992 |

Key outcome from this run:
- `noer22` level `8` produced almost the same size as `7z` (difference ~0.24 MB on ~96 MB input).
- `noer22` packed and extracted significantly faster than `7z` (`mx7` and `mx9`) on this dataset.
- `--parallel-crypto` remained slower for packing in this mixed workload and stays optional/experimental.
