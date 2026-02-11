use noer22::cli::{CipherChoice, PackArgs, UnpackArgs};
use noer22::{pack, unpack};
use serde::Serialize;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

const PASSWORD: &str = "benchpass";

#[derive(Debug, Clone)]
struct CliArgs {
    input: Option<PathBuf>,
    out_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
enum Target {
    Noer22 { level: i32, parallel_crypto: bool },
    SevenZip { mx: u8 },
}

#[derive(Debug, Serialize)]
struct BenchRow {
    name: String,
    pack_ms: f64,
    extract_ms: f64,
    archive_bytes: u64,
    ratio: f64,
}

#[derive(Debug, Serialize)]
struct BenchSummary {
    dataset_path: String,
    dataset_bytes: u64,
    rows: Vec<BenchRow>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("benchmark error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args(env::args_os().skip(1))?;
    let out_dir = args.out_dir.unwrap_or_else(default_output_dir);
    let dataset = match args.input {
        Some(path) => path,
        None => {
            let p = out_dir.join("dataset");
            create_synthetic_dataset(&p)?;
            p
        }
    };
    let archives_dir = out_dir.join("archives");
    let extract_dir = out_dir.join("extract");
    fs::create_dir_all(&archives_dir)?;
    fs::create_dir_all(&extract_dir)?;

    let dataset_bytes = dir_size(&dataset)?;
    let mut rows = Vec::new();

    let targets = bench_targets();
    for target in targets {
        let row = run_target(
            &target,
            &dataset,
            dataset_bytes,
            &archives_dir,
            &extract_dir,
        )?;
        rows.push(row);
    }

    rows.sort_by(|a, b| {
        a.pack_ms
            .partial_cmp(&b.pack_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let summary = BenchSummary {
        dataset_path: dataset.display().to_string(),
        dataset_bytes,
        rows,
    };

    let json_path = out_dir.join("benchmark_results.json");
    let md_path = out_dir.join("benchmark_results.md");
    fs::write(&json_path, serde_json::to_string_pretty(&summary)?)?;
    fs::write(&md_path, render_markdown(&summary))?;

    println!(
        "Dataset: {} ({:.2} MB)",
        summary.dataset_path,
        dataset_bytes as f64 / 1_048_576.0
    );
    println!();
    println!(
        "{:<20} {:>10} {:>11} {:>14} {:>8}",
        "name", "pack_ms", "extract_ms", "archive_mb", "ratio"
    );
    for row in &summary.rows {
        println!(
            "{:<20} {:>10.2} {:>11.2} {:>14.2} {:>8.4}",
            row.name,
            row.pack_ms,
            row.extract_ms,
            row.archive_bytes as f64 / 1_048_576.0,
            row.ratio
        );
    }
    println!();
    println!("JSON: {}", json_path.display());
    println!("Markdown: {}", md_path.display());
    Ok(())
}

fn parse_args(args: impl Iterator<Item = OsString>) -> Result<CliArgs, String> {
    let mut input = None;
    let mut out_dir = None;
    let mut iter = args.peekable();
    while let Some(flag) = iter.next() {
        let flag = flag.to_string_lossy();
        match flag.as_ref() {
            "--input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input = Some(PathBuf::from(value));
            }
            "--out-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--out-dir requires a path".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }
    Ok(CliArgs { input, out_dir })
}

fn print_help() {
    println!("noer22_bench");
    println!("Usage:");
    println!("  cargo run --release --bin noer22_bench -- [--input <path>] [--out-dir <path>]");
    println!();
    println!("If --input is omitted, a synthetic mixed dataset is generated automatically.");
}

fn bench_targets() -> Vec<Target> {
    let mut targets = vec![
        Target::Noer22 {
            level: 8,
            parallel_crypto: false,
        },
        Target::Noer22 {
            level: 8,
            parallel_crypto: true,
        },
        Target::Noer22 {
            level: 6,
            parallel_crypto: false,
        },
    ];

    if command_available("7z", &["i"]) {
        targets.push(Target::SevenZip { mx: 7 });
        targets.push(Target::SevenZip { mx: 9 });
    } else {
        println!("7z not found in PATH; skipping 7z rows.");
    }

    targets
}

fn run_target(
    target: &Target,
    dataset: &Path,
    dataset_bytes: u64,
    archives_dir: &Path,
    extract_root: &Path,
) -> Result<BenchRow, Box<dyn std::error::Error>> {
    match target {
        Target::Noer22 {
            level,
            parallel_crypto,
        } => {
            let name = if *parallel_crypto {
                format!("noer22_l{level}_parallel")
            } else {
                format!("noer22_l{level}")
            };
            let archive_path = archives_dir.join(format!("{name}.noer"));
            let extract_dir = extract_root.join(&name);
            recreate_dir(&extract_dir)?;

            let pack_start = Instant::now();
            pack::pack(PackArgs {
                inputs: vec![dataset.to_path_buf()],
                output: archive_path.clone(),
                password: Some(PASSWORD.to_string()),
                keyfile: None,
                age_recipients: Vec::new(),
                level: *level,
                cipher: CipherChoice::ChaCha20Poly1305,
                kdf_mem: 64,
                kdf_iters: 3,
                kdf_parallelism: 4,
                threads: None,
                parallel_crypto: *parallel_crypto,
                incremental_index: None,
                checksum: None,
                checksum_output: None,
            })?;
            let pack_ms = pack_start.elapsed().as_secs_f64() * 1000.0;

            let extract_start = Instant::now();
            unpack::unpack(UnpackArgs {
                archive: archive_path.clone(),
                password: Some(PASSWORD.to_string()),
                keyfile: None,
                age_identities: Vec::new(),
                output: Some(extract_dir),
                checksum_file: None,
                checksum_algo: None,
            })?;
            let extract_ms = extract_start.elapsed().as_secs_f64() * 1000.0;

            let archive_bytes = fs::metadata(&archive_path)?.len();
            Ok(BenchRow {
                name,
                pack_ms,
                extract_ms,
                archive_bytes,
                ratio: archive_bytes as f64 / dataset_bytes as f64,
            })
        }
        Target::SevenZip { mx } => {
            let name = format!("7z_mx{mx}");
            let archive_path = archives_dir.join(format!("{name}.7z"));
            let extract_dir = extract_root.join(&name);
            recreate_dir(&extract_dir)?;

            let pack_start = Instant::now();
            run_cmd(
                "7z",
                &[
                    "a",
                    "-t7z",
                    archive_path.to_string_lossy().as_ref(),
                    dataset.join("*").to_string_lossy().as_ref(),
                    &format!("-mx={mx}"),
                    "-m0=lzma2",
                    "-mhe=on",
                    &format!("-p{PASSWORD}"),
                    "-y",
                ],
            )?;
            let pack_ms = pack_start.elapsed().as_secs_f64() * 1000.0;

            let extract_start = Instant::now();
            run_cmd(
                "7z",
                &[
                    "x",
                    archive_path.to_string_lossy().as_ref(),
                    &format!("-o{}", extract_dir.to_string_lossy()),
                    &format!("-p{PASSWORD}"),
                    "-y",
                ],
            )?;
            let extract_ms = extract_start.elapsed().as_secs_f64() * 1000.0;

            let archive_bytes = fs::metadata(&archive_path)?.len();
            Ok(BenchRow {
                name,
                pack_ms,
                extract_ms,
                archive_bytes,
                ratio: archive_bytes as f64 / dataset_bytes as f64,
            })
        }
    }
}

fn command_available(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_cmd(bin: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("command failed: {bin} {}", args.join(" ")).into());
    }
    Ok(())
}

fn default_output_dir() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(format!("bench_run_{ts}"))
}

fn recreate_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    for entry in WalkDir::new(path).into_iter().flatten() {
        if entry.file_type().is_file() {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

fn create_synthetic_dataset(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;

    let mut compressible = File::create(path.join("compressible.txt"))?;
    let line = format!("NOER22-BENCH-LINE-{}\n", "A".repeat(200));
    for _ in 0..180_000 {
        compressible.write_all(line.as_bytes())?;
    }

    let mut random = File::create(path.join("random.bin"))?;
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut buf = [0u8; 64 * 1024];
    let mut written = 0u64;
    while written < 48 * 1024 * 1024 {
        for chunk in buf.chunks_exact_mut(8) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        let remaining = (48 * 1024 * 1024 - written) as usize;
        let take = remaining.min(buf.len());
        random.write_all(&buf[..take])?;
        written += take as u64;
    }

    let small = path.join("small_files");
    fs::create_dir_all(&small)?;
    for i in 0..6_000u32 {
        let mut f = File::create(small.join(format!("f_{i:05}.txt")))?;
        writeln!(f, "file:{i}")?;
        writeln!(f, "{}", "x".repeat(1_800))?;
    }

    let cwd = env::current_dir()?;
    let src = cwd.join("src");
    if src.exists() {
        copy_tree(&src, &path.join("src"))?;
    }
    let readme = cwd.join("README.md");
    if readme.exists() {
        fs::copy(readme, path.join("README.md"))?;
    }

    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in WalkDir::new(src).into_iter().flatten() {
        let rel = match entry.path().strip_prefix(src) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn render_markdown(summary: &BenchSummary) -> String {
    let mut s = String::new();
    s.push_str("# noer22 Benchmark Results\n\n");
    s.push_str(&format!(
        "Dataset: `{}` ({:.2} MB)\n\n",
        summary.dataset_path,
        summary.dataset_bytes as f64 / 1_048_576.0
    ));
    s.push_str("| name | pack_ms | extract_ms | archive_mb | ratio |\n");
    s.push_str("|---|---:|---:|---:|---:|\n");
    for row in &summary.rows {
        s.push_str(&format!(
            "| {} | {:.2} | {:.2} | {:.2} | {:.4} |\n",
            row.name,
            row.pack_ms,
            row.extract_ms,
            row.archive_bytes as f64 / 1_048_576.0,
            row.ratio
        ));
    }
    s
}
