# Benchmark Snapshot

Date: 2026-02-11  
Host: Windows 11, PowerShell 5.1, NanaZip (`7z`) + WinRAR (`C:\\Program Files\\WinRAR\\rar.exe`).

## Dataset

Mixed workload (`100,841,411` bytes / `96.17 MB`):
- highly compressible text block
- incompressible random block
- thousands of small files
- project `src/` + `README.md` snapshot

## Commands Compared

- `noer22` pack/unpack (password auth)
- `7z` pack/extract (`-mhe=on -p...`)
- `rar` pack/extract (`-hp...`)

## Methodology

- 1 warmup round + 5 measured rounds
- 20 ms process sampling interval
- metrics shown as `mean +/- standard deviation`
- peak RSS and peak CPU sampled independently for `pack` and `extract`

## Results

| name | pack_ms (mean+/-sd) | extract_ms (mean+/-sd) | archive_mb | ratio | pack_peak_rss_mb | extract_peak_rss_mb | pack_peak_cpu_% | extract_peak_cpu_% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| noer22_l8_parallel | 908.74 +/- 83.67 | 13743.36 +/- 7412.83 | 48.32 | 0.5024 | 236.76 | 81.28 | 158.46 | 109.12 |
| noer22_l6 | 951.49 +/- 246.87 | 13216.20 +/- 5426.24 | 48.32 | 0.5024 | 187.41 | 81.72 | 156.74 | 106.15 |
| noer22_l8 | 1156.85 +/- 726.63 | 12797.50 +/- 9583.49 | 48.32 | 0.5024 | 233.52 | 79.59 | 166.15 | 106.15 |
| rar_m3 | 7378.83 +/- 428.29 | 3349.84 +/- 436.91 | 49.06 | 0.5102 | 303.85 | 51.64 | 895.77 | 282.64 |
| rar_m5 | 7385.40 +/- 332.96 | 3118.61 +/- 314.12 | 49.06 | 0.5102 | 575.02 | 51.64 | 749.17 | 261.57 |
| 7z_mx9 | 8545.94 +/- 113.20 | 4196.58 +/- 439.30 | 48.09 | 0.5000 | 997.64 | 156.07 | 229.01 | 100.00 |
| 7z_mx7 | 8590.20 +/- 121.71 | 5748.21 +/- 4084.22 | 48.09 | 0.5000 | 1001.44 | 156.08 | 239.56 | 90.77 |

## Takeaways from This Run

- In this dataset, `noer22` packed substantially faster than tested `7z`/`rar` settings.
- Archive size was close to `7z` and smaller than tested `rar` settings.
- `noer22` peak memory was materially lower than `7z` in this run.
- Extract timings showed high variance under repeated loops; validate on your own hardware before tuning decisions.

## Reproducing

Example:

```bash
cargo run --release --bin noer22_bench -- \
  --input ./your_dataset \
  --rounds 5 \
  --warmup-rounds 1 \
  --sample-ms 20
```

Generated outputs:
- `bench_run_<timestamp>/benchmark_results.json`
- `bench_run_<timestamp>/benchmark_results.md`

Notes:
- If `--input` is omitted, a synthetic mixed dataset is generated automatically.
- Comparison rows are only included when `7z`/`7zz` and/or `rar` binaries are available in the host environment.
- Benchmark output directories are ignored by `.gitignore` by default.
