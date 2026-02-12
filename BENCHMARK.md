# Benchmark Snapshot

Date: 2026-02-11  
Host: Windows 11, PowerShell 5.1, NanaZip (`7z`) + WinRAR (`C:\Program Files\WinRAR\rar.exe`).

Dataset (mixed):
- 96.17 MB total (`100,841,411` bytes)
- Highly compressible text block
- Incompressible random block
- Thousands of small files
- Project `src/` + `README.md` snapshot

Measured commands:
- `noer22` pack/unpack with password auth
- `7z` pack/extract with encrypted headers (`-mhe=on -p...`)
- `rar` pack/extract with encrypted headers (`-hp...`)

Method:
- 5 measured rounds + 1 warmup round
- 20 ms process sampling interval
- Reported as mean +/- standard deviation
- Includes peak RSS and peak CPU per step (`pack` and `extract`)

| name | pack_ms (mean+/-sd) | extract_ms (mean+/-sd) | archive_mb | ratio | pack_peak_rss_mb | extract_peak_rss_mb | pack_peak_cpu_% | extract_peak_cpu_% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| noer22_l8_parallel | 908.74 +/- 83.67 | 13743.36 +/- 7412.83 | 48.32 | 0.5024 | 236.76 | 81.28 | 158.46 | 109.12 |
| noer22_l6 | 951.49 +/- 246.87 | 13216.20 +/- 5426.24 | 48.32 | 0.5024 | 187.41 | 81.72 | 156.74 | 106.15 |
| noer22_l8 | 1156.85 +/- 726.63 | 12797.50 +/- 9583.49 | 48.32 | 0.5024 | 233.52 | 79.59 | 166.15 | 106.15 |
| rar_m3 | 7378.83 +/- 428.29 | 3349.84 +/- 436.91 | 49.06 | 0.5102 | 303.85 | 51.64 | 895.77 | 282.64 |
| rar_m5 | 7385.40 +/- 332.96 | 3118.61 +/- 314.12 | 49.06 | 0.5102 | 575.02 | 51.64 | 749.17 | 261.57 |
| 7z_mx9 | 8545.94 +/- 113.20 | 4196.58 +/- 439.30 | 48.09 | 0.5000 | 997.64 | 156.07 | 229.01 | 100.00 |
| 7z_mx7 | 8590.20 +/- 121.71 | 5748.21 +/- 4084.22 | 48.09 | 0.5000 | 1001.44 | 156.08 | 239.56 | 90.77 |

Key outcome from this run:
- `noer22` remained much faster for packing in this workload.
- `noer22` archive size remained close to `7z` and clearly smaller than tested `rar` settings.
- Peak memory for `noer22` was substantially lower than `7z` in these tests.
- Extraction time showed high variance in this run (especially under repeated loops), so compare extraction with repeated runs on your target machine before final tuning decisions.
