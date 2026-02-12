use noer22::cli::{CipherChoice, PackArgs, UnpackArgs};
use noer22::{pack, unpack};
use serde::Serialize;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, MINIMUM_CPU_UPDATE_INTERVAL};
use walkdir::WalkDir;

const PASSWORD: &str = "benchpass";
const DEFAULT_ROUNDS: usize = 5;
const DEFAULT_WARMUP_ROUNDS: usize = 1;
const DEFAULT_SAMPLE_MS: u64 = 20;

#[derive(Debug, Clone)]
struct CliArgs {
    input: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    rounds: usize,
    warmup_rounds: usize,
    sample_ms: u64,
}

#[derive(Debug, Clone)]
enum Target {
    Noer22 { level: i32, parallel_crypto: bool },
    SevenZip { bin: String, mx: u8 },
    Rar { bin: String, m: u8 },
}

#[derive(Debug, Serialize, Clone)]
struct StepSample {
    elapsed_ms: f64,
    peak_rss_bytes: u64,
    peak_cpu_pct: f64,
}

#[derive(Debug, Serialize, Clone)]
struct RoundMetrics {
    round: usize,
    pack: StepSample,
    extract: StepSample,
    archive_bytes: u64,
}

#[derive(Debug, Serialize)]
struct BenchRow {
    name: String,
    rounds: usize,
    pack_ms_mean: f64,
    pack_ms_stddev: f64,
    pack_ms_min: f64,
    pack_ms_max: f64,
    extract_ms_mean: f64,
    extract_ms_stddev: f64,
    extract_ms_min: f64,
    extract_ms_max: f64,
    archive_bytes_mean: u64,
    ratio_mean: f64,
    pack_peak_rss_mb_mean: f64,
    extract_peak_rss_mb_mean: f64,
    pack_peak_cpu_pct_mean: f64,
    extract_peak_cpu_pct_mean: f64,
    round_details: Vec<RoundMetrics>,
}

#[derive(Debug, Serialize)]
struct BenchSummary {
    dataset_path: String,
    dataset_bytes: u64,
    rounds: usize,
    warmup_rounds: usize,
    sample_ms: u64,
    rows: Vec<BenchRow>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcessReading {
    peak_rss_bytes: u64,
    peak_cpu_pct: f64,
}

struct ProcessSampler {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<ProcessReading>>,
}

impl ProcessSampler {
    fn spawn(pid_u32: u32, sample_ms: u64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let interval = Duration::from_millis(sample_ms.max(5)).max(MINIMUM_CPU_UPDATE_INTERVAL);
        let handle = thread::spawn(move || sample_process(pid_u32, interval, stop_bg));
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn finish(&mut self) -> ProcessReading {
        self.stop.store(true, Ordering::Relaxed);
        match self.handle.take() {
            Some(handle) => handle.join().unwrap_or_default(),
            None => ProcessReading::default(),
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("benchmark error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_args(env::args_os().skip(1))?;
    let out_dir = args.out_dir.clone().unwrap_or_else(default_output_dir);
    let dataset = match args.input.clone() {
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
    let targets = bench_targets();
    let mut rows = Vec::new();

    println!(
        "Dataset: {} ({:.2} MB)",
        dataset.display(),
        dataset_bytes as f64 / 1_048_576.0
    );
    println!(
        "Rounds: {} measured + {} warmup, sampler interval: {} ms",
        args.rounds, args.warmup_rounds, args.sample_ms
    );
    println!();

    for target in &targets {
        println!("Running target: {}", target_name(target));
        let row = run_target(
            target,
            &dataset,
            dataset_bytes,
            &archives_dir,
            &extract_dir,
            &args,
        )?;
        rows.push(row);
    }

    rows.sort_by(|a, b| {
        a.pack_ms_mean
            .partial_cmp(&b.pack_ms_mean)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let summary = BenchSummary {
        dataset_path: dataset.display().to_string(),
        dataset_bytes,
        rounds: args.rounds,
        warmup_rounds: args.warmup_rounds,
        sample_ms: args.sample_ms,
        rows,
    };

    let json_path = out_dir.join("benchmark_results.json");
    let md_path = out_dir.join("benchmark_results.md");
    fs::write(&json_path, serde_json::to_string_pretty(&summary)?)?;
    fs::write(&md_path, render_markdown(&summary))?;

    println!();
    println!(
        "{:<20} {:>11} {:>11} {:>11} {:>11} {:>10} {:>8} {:>11} {:>11} {:>9} {:>9}",
        "name",
        "pack_mean",
        "pack_sd",
        "extract_m",
        "extract_sd",
        "arch_mb",
        "ratio",
        "pack_rss",
        "extract_rss",
        "pack_cpu",
        "extract_cpu"
    );
    for row in &summary.rows {
        println!(
            "{:<20} {:>11.2} {:>11.2} {:>11.2} {:>11.2} {:>10.2} {:>8.4} {:>11.2} {:>11.2} {:>9.2} {:>9.2}",
            row.name,
            row.pack_ms_mean,
            row.pack_ms_stddev,
            row.extract_ms_mean,
            row.extract_ms_stddev,
            row.archive_bytes_mean as f64 / 1_048_576.0,
            row.ratio_mean,
            row.pack_peak_rss_mb_mean,
            row.extract_peak_rss_mb_mean,
            row.pack_peak_cpu_pct_mean,
            row.extract_peak_cpu_pct_mean,
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
    let mut rounds = DEFAULT_ROUNDS;
    let mut warmup_rounds = DEFAULT_WARMUP_ROUNDS;
    let mut sample_ms = DEFAULT_SAMPLE_MS;
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
            "--rounds" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--rounds requires a number".to_string())?;
                rounds = value
                    .to_string_lossy()
                    .parse::<usize>()
                    .map_err(|_| "--rounds must be a positive integer".to_string())?;
            }
            "--warmup-rounds" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--warmup-rounds requires a number".to_string())?;
                warmup_rounds = value
                    .to_string_lossy()
                    .parse::<usize>()
                    .map_err(|_| "--warmup-rounds must be a non-negative integer".to_string())?;
            }
            "--sample-ms" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--sample-ms requires a number".to_string())?;
                sample_ms = value
                    .to_string_lossy()
                    .parse::<u64>()
                    .map_err(|_| "--sample-ms must be a positive integer".to_string())?;
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

    if rounds == 0 {
        return Err("--rounds must be >= 1".to_string());
    }
    if sample_ms == 0 {
        return Err("--sample-ms must be >= 1".to_string());
    }

    Ok(CliArgs {
        input,
        out_dir,
        rounds,
        warmup_rounds,
        sample_ms,
    })
}

fn print_help() {
    println!("noer22_bench");
    println!("Usage:");
    println!(
        "  cargo run --release --bin noer22_bench -- [--input <path>] [--out-dir <path>] [--rounds <N>] [--warmup-rounds <N>] [--sample-ms <N>]"
    );
    println!();
    println!("Defaults: --rounds 5 --warmup-rounds 1 --sample-ms 20");
    println!("If --input is omitted, a synthetic mixed dataset is generated automatically.");
    println!("If available, 7z/7zz and rar rows are added automatically.");
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

    if let Some(bin) = detect_7z_bin() {
        targets.push(Target::SevenZip {
            bin: bin.clone(),
            mx: 7,
        });
        targets.push(Target::SevenZip { bin, mx: 9 });
    } else {
        println!("7z not found in PATH/default locations; skipping 7z rows.");
    }

    if let Some(bin) = detect_rar_bin() {
        targets.push(Target::Rar {
            bin: bin.clone(),
            m: 3,
        });
        targets.push(Target::Rar { bin, m: 5 });
    } else {
        println!("rar not found in PATH/default locations; skipping rar rows.");
    }

    targets
}

fn run_target(
    target: &Target,
    dataset: &Path,
    dataset_bytes: u64,
    archives_dir: &Path,
    extract_root: &Path,
    args: &CliArgs,
) -> Result<BenchRow, Box<dyn Error>> {
    let name = target_name(target);

    for idx in 0..args.warmup_rounds {
        let tag = format!("warmup_{:02}", idx + 1);
        let _ = run_target_once(
            target,
            dataset,
            archives_dir,
            extract_root,
            &name,
            &tag,
            args,
        )?;
    }

    let mut rounds = Vec::with_capacity(args.rounds);
    for idx in 0..args.rounds {
        let round_num = idx + 1;
        let tag = format!("round_{:02}", round_num);
        let mut metrics = run_target_once(
            target,
            dataset,
            archives_dir,
            extract_root,
            &name,
            &tag,
            args,
        )?;
        metrics.round = round_num;
        rounds.push(metrics);
    }

    Ok(aggregate_row(name, dataset_bytes, rounds))
}

fn run_target_once(
    target: &Target,
    dataset: &Path,
    archives_dir: &Path,
    extract_root: &Path,
    name: &str,
    run_tag: &str,
    args: &CliArgs,
) -> Result<RoundMetrics, Box<dyn Error>> {
    match target {
        Target::Noer22 {
            level,
            parallel_crypto,
        } => {
            let archive_path = archives_dir.join(format!("{name}_{run_tag}.noer"));
            let extract_dir = extract_root.join(format!("{name}_{run_tag}"));
            if archive_path.exists() {
                fs::remove_file(&archive_path)?;
            }
            recreate_dir(&extract_dir)?;

            let (_, pack_sample) = measure_current_process(args.sample_ms, || {
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
                Ok(())
            })?;

            let (_, extract_sample) = measure_current_process(args.sample_ms, || {
                unpack::unpack(UnpackArgs {
                    archive: archive_path.clone(),
                    password: Some(PASSWORD.to_string()),
                    keyfile: None,
                    age_identities: Vec::new(),
                    output: Some(extract_dir),
                    checksum_file: None,
                    checksum_algo: None,
                })?;
                Ok(())
            })?;

            let archive_bytes = fs::metadata(&archive_path)?.len();
            Ok(RoundMetrics {
                round: 0,
                pack: pack_sample,
                extract: extract_sample,
                archive_bytes,
            })
        }
        Target::SevenZip { bin, mx } => {
            let archive_path = archives_dir.join(format!("{name}_{run_tag}.7z"));
            let extract_dir = extract_root.join(format!("{name}_{run_tag}"));
            if archive_path.exists() {
                fs::remove_file(&archive_path)?;
            }
            recreate_dir(&extract_dir)?;

            let pack_sample = run_cmd_measured(
                bin,
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
                args.sample_ms,
            )?;

            let extract_sample = run_cmd_measured(
                bin,
                &[
                    "x",
                    archive_path.to_string_lossy().as_ref(),
                    &format!("-o{}", extract_dir.to_string_lossy()),
                    &format!("-p{PASSWORD}"),
                    "-y",
                ],
                args.sample_ms,
            )?;

            let archive_bytes = fs::metadata(&archive_path)?.len();
            Ok(RoundMetrics {
                round: 0,
                pack: pack_sample,
                extract: extract_sample,
                archive_bytes,
            })
        }
        Target::Rar { bin, m } => {
            let archive_path = archives_dir.join(format!("{name}_{run_tag}.rar"));
            let extract_dir = extract_root.join(format!("{name}_{run_tag}"));
            if archive_path.exists() {
                fs::remove_file(&archive_path)?;
            }
            recreate_dir(&extract_dir)?;

            let pack_sample = run_cmd_measured(
                bin,
                &[
                    "a",
                    "-idq",
                    &format!("-m{m}"),
                    "-ep1",
                    "-r",
                    &format!("-hp{PASSWORD}"),
                    archive_path.to_string_lossy().as_ref(),
                    dataset.join("*").to_string_lossy().as_ref(),
                ],
                args.sample_ms,
            )?;

            let extract_sample = run_cmd_measured(
                bin,
                &[
                    "x",
                    "-idq",
                    "-o+",
                    &format!("-p{PASSWORD}"),
                    archive_path.to_string_lossy().as_ref(),
                    extract_dir.to_string_lossy().as_ref(),
                ],
                args.sample_ms,
            )?;

            let archive_bytes = fs::metadata(&archive_path)?.len();
            Ok(RoundMetrics {
                round: 0,
                pack: pack_sample,
                extract: extract_sample,
                archive_bytes,
            })
        }
    }
}

fn aggregate_row(name: String, dataset_bytes: u64, rounds: Vec<RoundMetrics>) -> BenchRow {
    let pack: Vec<f64> = rounds.iter().map(|r| r.pack.elapsed_ms).collect();
    let extract: Vec<f64> = rounds.iter().map(|r| r.extract.elapsed_ms).collect();
    let archive: Vec<f64> = rounds.iter().map(|r| r.archive_bytes as f64).collect();
    let pack_rss_mb: Vec<f64> = rounds
        .iter()
        .map(|r| r.pack.peak_rss_bytes as f64 / 1_048_576.0)
        .collect();
    let extract_rss_mb: Vec<f64> = rounds
        .iter()
        .map(|r| r.extract.peak_rss_bytes as f64 / 1_048_576.0)
        .collect();
    let pack_cpu_pct: Vec<f64> = rounds.iter().map(|r| r.pack.peak_cpu_pct).collect();
    let extract_cpu_pct: Vec<f64> = rounds.iter().map(|r| r.extract.peak_cpu_pct).collect();

    let pack_ms_mean = mean(&pack);
    let extract_ms_mean = mean(&extract);
    let archive_mean = mean(&archive);

    BenchRow {
        name,
        rounds: rounds.len(),
        pack_ms_mean,
        pack_ms_stddev: stddev(&pack, pack_ms_mean),
        pack_ms_min: min_value(&pack),
        pack_ms_max: max_value(&pack),
        extract_ms_mean,
        extract_ms_stddev: stddev(&extract, extract_ms_mean),
        extract_ms_min: min_value(&extract),
        extract_ms_max: max_value(&extract),
        archive_bytes_mean: archive_mean.round() as u64,
        ratio_mean: if dataset_bytes == 0 {
            0.0
        } else {
            archive_mean / dataset_bytes as f64
        },
        pack_peak_rss_mb_mean: mean(&pack_rss_mb),
        extract_peak_rss_mb_mean: mean(&extract_rss_mb),
        pack_peak_cpu_pct_mean: mean(&pack_cpu_pct),
        extract_peak_cpu_pct_mean: mean(&extract_cpu_pct),
        round_details: rounds,
    }
}

fn detect_7z_bin() -> Option<String> {
    let mut candidates = vec!["7zz".to_string(), "7z".to_string()];
    if cfg!(windows) {
        candidates.push(r"C:\Program Files\7-Zip\7z.exe".to_string());
        candidates.push(r"C:\Program Files\NanaZip\7z.exe".to_string());
    }
    detect_bin_with_args(&candidates, &["i"])
}

fn detect_rar_bin() -> Option<String> {
    let mut candidates = vec!["rar".to_string()];
    if cfg!(windows) {
        candidates.push(r"C:\Program Files\WinRAR\rar.exe".to_string());
        candidates.push(r"C:\Program Files (x86)\WinRAR\rar.exe".to_string());
    }
    detect_bin_with_args(&candidates, &["-?"])
}

fn detect_bin_with_args(candidates: &[String], probe_args: &[&str]) -> Option<String> {
    for candidate in candidates {
        if command_available(candidate, probe_args) {
            return Some(candidate.clone());
        }
    }
    None
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

fn run_cmd_measured(
    bin: &str,
    args: &[&str],
    sample_ms: u64,
) -> Result<StepSample, Box<dyn Error>> {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut sampler = ProcessSampler::spawn(child.id(), sample_ms);
    let started = Instant::now();
    let status = child.wait()?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let reading = sampler.finish();
    if !status.success() {
        return Err(format!("command failed: {bin} {}", args.join(" ")).into());
    }
    Ok(StepSample {
        elapsed_ms,
        peak_rss_bytes: reading.peak_rss_bytes,
        peak_cpu_pct: reading.peak_cpu_pct,
    })
}

fn measure_current_process<T, F>(
    sample_ms: u64,
    operation: F,
) -> Result<(T, StepSample), Box<dyn Error>>
where
    F: FnOnce() -> Result<T, Box<dyn Error>>,
{
    let mut sampler = ProcessSampler::spawn(std::process::id(), sample_ms);
    let started = Instant::now();
    let result = operation();
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let reading = sampler.finish();
    let value = result?;
    Ok((
        value,
        StepSample {
            elapsed_ms,
            peak_rss_bytes: reading.peak_rss_bytes,
            peak_cpu_pct: reading.peak_cpu_pct,
        },
    ))
}

fn sample_process(pid_u32: u32, interval: Duration, stop: Arc<AtomicBool>) -> ProcessReading {
    let pid = Pid::from_u32(pid_u32);
    let mut system = System::new();
    let refresh_kind = ProcessRefreshKind::nothing().with_memory().with_cpu();
    let mut out = ProcessReading::default();

    system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, refresh_kind);
    if let Some(proc_) = system.process(pid) {
        out.peak_rss_bytes = out.peak_rss_bytes.max(proc_.memory());
        out.peak_cpu_pct = out.peak_cpu_pct.max(proc_.cpu_usage() as f64);
    }

    loop {
        thread::sleep(interval);
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, refresh_kind);
        if let Some(proc_) = system.process(pid) {
            out.peak_rss_bytes = out.peak_rss_bytes.max(proc_.memory());
            out.peak_cpu_pct = out.peak_cpu_pct.max(proc_.cpu_usage() as f64);
        } else if stop.load(Ordering::Relaxed) {
            break;
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }
    }

    system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, refresh_kind);
    if let Some(proc_) = system.process(pid) {
        out.peak_rss_bytes = out.peak_rss_bytes.max(proc_.memory());
        out.peak_cpu_pct = out.peak_cpu_pct.max(proc_.cpu_usage() as f64);
    }
    out
}

fn target_name(target: &Target) -> String {
    match target {
        Target::Noer22 {
            level,
            parallel_crypto,
        } => {
            if *parallel_crypto {
                format!("noer22_l{level}_parallel")
            } else {
                format!("noer22_l{level}")
            }
        }
        Target::SevenZip { mx, .. } => format!("7z_mx{mx}"),
        Target::Rar { m, .. } => format!("rar_m{m}"),
    }
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
    s.push_str(&format!(
        "Measured rounds: {} | Warmup rounds: {} | Sampling interval: {} ms\n\n",
        summary.rounds, summary.warmup_rounds, summary.sample_ms
    ));
    s.push_str("| name | pack_ms (mean+/-sd) | extract_ms (mean+/-sd) | archive_mb | ratio | pack_peak_rss_mb | extract_peak_rss_mb | pack_peak_cpu_% | extract_peak_cpu_% |\n");
    s.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in &summary.rows {
        s.push_str(&format!(
            "| {} | {:.2} +/- {:.2} | {:.2} +/- {:.2} | {:.2} | {:.4} | {:.2} | {:.2} | {:.2} | {:.2} |\n",
            row.name,
            row.pack_ms_mean,
            row.pack_ms_stddev,
            row.extract_ms_mean,
            row.extract_ms_stddev,
            row.archive_bytes_mean as f64 / 1_048_576.0,
            row.ratio_mean,
            row.pack_peak_rss_mb_mean,
            row.extract_peak_rss_mb_mean,
            row.pack_peak_cpu_pct_mean,
            row.extract_peak_cpu_pct_mean,
        ));
    }
    s
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn stddev(values: &[f64], mean_value: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|v| {
            let d = *v - mean_value;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

fn min_value(values: &[f64]) -> f64 {
    values.iter().copied().reduce(f64::min).unwrap_or(0.0)
}

fn max_value(values: &[f64]) -> f64 {
    values.iter().copied().reduce(f64::max).unwrap_or(0.0)
}
