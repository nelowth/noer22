use crate::agewrap;
use crate::checksum::{self, ChecksumAlgo};
use crate::cli::{ChecksumChoice, CipherChoice, PackArgs};
use crate::compression;
use crate::crypto::{self, EncryptWriter};
use crate::error::{NoerError, Result};
use crate::format::{CompressionAlgo, CryptoAlgo, Header, HeaderFlags, KdfParams};
use crate::incremental::{self, FileProbe};
use crate::metadata::{self, FileEntry, Metadata};
use crate::utils::{self, ConcatReader, ProgressReader, RelPathSet};
use rayon::prelude::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tempfile::NamedTempFile;
use walkdir::WalkDir;
use zeroize::Zeroizing;

const PARALLEL_BATCH_CHUNKS: usize = 1024;

pub fn pack(args: PackArgs) -> Result<()> {
    if args.inputs.is_empty() {
        return Err(NoerError::InvalidFormat("no input provided".into()));
    }
    let use_age_recipients = !args.age_recipients.is_empty();
    if use_age_recipients && (args.password.is_some() || args.keyfile.is_some()) {
        return Err(NoerError::InvalidFormat(
            "use either password/keyfile or --age-recipient, not both".into(),
        ));
    }
    if !use_age_recipients && args.password.is_none() && args.keyfile.is_none() {
        return Err(NoerError::InvalidFormat(
            "password, keyfile, or age recipient is required".into(),
        ));
    }
    if args.level < -22 || args.level > 22 {
        return Err(NoerError::InvalidFormat("invalid compression level".into()));
    }
    if args.kdf_mem == 0 || args.kdf_iters == 0 || args.kdf_parallelism == 0 {
        return Err(NoerError::InvalidFormat(
            "invalid Argon2id parameters".into(),
        ));
    }

    let mut entries = collect_entries(&args.inputs)?;
    if entries.is_empty() {
        return Err(NoerError::InvalidFormat("no files found".into()));
    }
    entries.sort_by(|a, b| a.meta.path.cmp(&b.meta.path));

    let mut incremental_state: Option<IncrementalState> = None;
    if let Some(index_path) = args.incremental_index.as_ref() {
        let previous = incremental::load_or_default(index_path)?;
        let (filtered, next_index, stats, had_input_files, tombstones) =
            apply_incremental_filter(entries, &previous)?;

        println!(
            "Incremental scan: prev={}, scanned={}, changed={}, skipped={}, removed={}",
            stats.previous_files,
            stats.scanned_files,
            stats.changed_files,
            stats.skipped_files,
            stats.removed_files
        );

        entries = filtered;
        incremental_state = Some(IncrementalState {
            index_path: index_path.clone(),
            next_index,
            tombstones,
        });

        let changed_files = entries
            .iter()
            .filter(|e| !e.meta.is_dir && !e.meta.deleted)
            .count();
        if had_input_files && changed_files == 0 && tombstones == 0 {
            println!("No changed files detected. Skipping archive creation.");
            if let Some(state) = incremental_state.as_ref() {
                incremental::save(&state.index_path, &state.next_index)?;
                println!("Incremental index updated: {}", state.index_path.display());
            }
            return Ok(());
        }
    }

    entries.sort_by(|a, b| a.meta.path.cmp(&b.meta.path));

    let total_size: u64 = entries
        .iter()
        .filter(|e| !e.meta.is_dir && !e.meta.deleted)
        .map(|e| e.meta.size)
        .sum();
    let metadata = Metadata {
        files: entries.iter().map(|e| e.meta.clone()).collect(),
    };
    let meta_bytes = metadata::serialize(&metadata)?;
    let est_size = estimate_archive_size(total_size, meta_bytes.len() as u64, args.level);
    println!(
        "Estimated output: ~{} (input {})",
        utils::human_bytes(est_size),
        utils::human_bytes(total_size)
    );

    let salt = crypto::random_salt()?;
    let nonce = crypto::random_nonce()?;
    let kdf = KdfParams {
        mem_kib: args.kdf_mem.saturating_mul(1024),
        iterations: args.kdf_iters,
        parallelism: args.kdf_parallelism,
    };

    let mut wrapped_file_key: Option<Vec<u8>> = None;
    let (key, keyfile_required) = if use_age_recipients {
        let mut file_key = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(file_key.as_mut())
            .map_err(|_| NoerError::InvalidFormat("failed to generate file key".into()))?;
        wrapped_file_key = Some(agewrap::encrypt_file_key(&file_key, &args.age_recipients)?);
        (file_key, false)
    } else {
        let keyfile_bytes = args
            .keyfile
            .as_ref()
            .map(|path| crypto::read_keyfile(path))
            .transpose()?;
        let password = args.password.map(Zeroizing::new);
        let password_ref = password.as_deref().map(|s| s.as_str());
        let key = crypto::derive_key_material(
            password_ref,
            keyfile_bytes.as_deref().map(|v| v.as_slice()),
            &salt,
            kdf,
        )?;
        (key, keyfile_bytes.is_some())
    };

    let header = Header::new(
        CompressionAlgo::Zstd,
        args.cipher.into(),
        salt,
        nonce,
        kdf,
        HeaderFlags {
            keyfile_required,
            incremental: args.incremental_index.is_some(),
            age_recipients: use_age_recipients,
        },
    );
    let header_bytes = header.to_bytes();
    let mut encryptor =
        crypto::ChunkEncryptor::new(header.crypto, key.as_ref(), nonce, header_bytes.to_vec())?;

    let out_file = File::create(&args.output)?;
    let mut writer = BufWriter::new(out_file);
    writer.write_all(&header_bytes)?;
    if let Some(envelope) = wrapped_file_key.as_ref() {
        if envelope.len() > u32::MAX as usize {
            return Err(NoerError::InvalidFormat("age envelope too large".into()));
        }
        writer.write_all(&(envelope.len() as u32).to_le_bytes())?;
        writer.write_all(envelope)?;
    }
    encryptor.encrypt_chunk(&meta_bytes, &mut writer)?;

    let paths = payload_paths(&entries)?;
    let threads = args.threads.unwrap_or_else(utils::default_threads);

    if args.parallel_crypto {
        println!(
            "Experimental path enabled: deterministic parallel chunk encryption (threads={threads})"
        );
        write_payload_parallel(
            &mut writer,
            ParallelPayloadConfig {
                paths,
                total_size,
                crypto_algo: header.crypto,
                key: key.as_ref(),
                nonce,
                aad: &header_bytes,
                level: args.level,
                threads,
            },
        )?;
    } else {
        let encrypt_writer = EncryptWriter::new(writer, encryptor);
        let mut writer =
            write_payload_streaming(paths, total_size, encrypt_writer, args.level, threads)?;
        writer.flush()?;
    }

    if let Some(algo) = args.checksum {
        let out =
            checksum::write_sidecar(&args.output, algo.into(), args.checksum_output.as_deref())?;
        println!("External checksum written: {}", out.display());
    }

    if let Some(state) = incremental_state {
        incremental::save(&state.index_path, &state.next_index)?;
        println!("Incremental index updated: {}", state.index_path.display());
        if state.tombstones > 0 {
            println!(
                "Incremental tombstones emitted: {} removed file(s)",
                state.tombstones
            );
        }
    }

    Ok(())
}

fn payload_paths(entries: &[SourceEntry]) -> Result<Vec<PathBuf>> {
    entries
        .iter()
        .filter(|e| !e.meta.is_dir && !e.meta.deleted)
        .map(|e| {
            e.abs_path.clone().ok_or_else(|| {
                NoerError::InvalidFormat("missing source path for payload entry".into())
            })
        })
        .collect()
}

fn write_payload_streaming(
    paths: Vec<PathBuf>,
    total_size: u64,
    encrypt_writer: EncryptWriter<BufWriter<File>>,
    level: i32,
    threads: usize,
) -> Result<BufWriter<File>> {
    let concat = ConcatReader::new(paths);
    let pb = utils::progress_bar(total_size, "packing");
    let mut reader = ProgressReader::new(concat, pb.clone());

    let encrypt_writer = compression::compress_reader_to_writer(
        &mut reader,
        encrypt_writer,
        level,
        threads,
        Some(total_size),
    )?;
    let mut writer = encrypt_writer.finish()?;
    writer.flush()?;
    pb.finish_and_clear();
    Ok(writer)
}

fn write_payload_parallel(
    writer: &mut BufWriter<File>,
    cfg: ParallelPayloadConfig<'_>,
) -> Result<()> {
    let ParallelPayloadConfig {
        paths,
        total_size,
        crypto_algo,
        key,
        nonce,
        aad,
        level,
        threads,
    } = cfg;

    let temp = NamedTempFile::new()?;

    {
        let temp_file = temp.reopen()?;
        let temp_writer = BufWriter::new(temp_file);
        let concat = ConcatReader::new(paths);
        let compress_pb = utils::progress_bar(total_size, "compressing");
        let mut reader = ProgressReader::new(concat, compress_pb.clone());
        let mut temp_writer = compression::compress_reader_to_writer(
            &mut reader,
            temp_writer,
            level,
            threads,
            Some(total_size),
        )?;
        temp_writer.flush()?;
        compress_pb.finish_and_clear();
    }

    let compressed_size = fs::metadata(temp.path())?.len();
    let encrypt_pb = utils::progress_bar(compressed_size, "encrypting");
    let mut temp_reader = BufReader::with_capacity(1024 * 1024, File::open(temp.path())?);

    let mut chunk_index: usize = 1;
    loop {
        let mut jobs: Vec<(usize, Vec<u8>)> = Vec::with_capacity(PARALLEL_BATCH_CHUNKS);
        for _ in 0..PARALLEL_BATCH_CHUNKS {
            let mut buf = vec![0u8; crypto::CHUNK_SIZE];
            let n = temp_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            buf.truncate(n);
            jobs.push((chunk_index, buf));
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| NoerError::InvalidFormat("chunk index overflow".into()))?;
        }

        if jobs.is_empty() {
            break;
        }

        let encrypted_batches: Vec<Result<(Vec<u8>, usize)>> = jobs
            .into_par_iter()
            .map(|(idx, data)| {
                let written_plain = data.len();
                let encoded =
                    crypto::encrypt_chunk_at_index(crypto_algo, key, nonce, aad, idx, &data)?;
                Ok((encoded, written_plain))
            })
            .collect();

        for result in encrypted_batches {
            let (encoded, plain_len) = result?;
            writer.write_all(&encoded)?;
            encrypt_pb.inc(plain_len as u64);
        }
    }

    encrypt_pb.finish_and_clear();
    writer.flush()?;
    Ok(())
}

struct ParallelPayloadConfig<'a> {
    paths: Vec<PathBuf>,
    total_size: u64,
    crypto_algo: CryptoAlgo,
    key: &'a [u8],
    nonce: [u8; 12],
    aad: &'a [u8],
    level: i32,
    threads: usize,
}

struct IncrementalState {
    index_path: PathBuf,
    next_index: incremental::IncrementalIndex,
    tombstones: usize,
}

struct SourceEntry {
    abs_path: Option<PathBuf>,
    meta: FileEntry,
}

#[derive(Clone, Copy)]
enum InputKind {
    File,
    Dir,
}

struct InputSpec {
    abs_path: PathBuf,
    kind: InputKind,
    base_name: String,
}

fn collect_entries(inputs: &[PathBuf]) -> Result<Vec<SourceEntry>> {
    let cwd = std::env::current_dir()?;
    let mut specs = Vec::with_capacity(inputs.len());
    let mut base_counts = HashMap::<String, usize>::new();

    for (idx, input) in inputs.iter().enumerate() {
        let abs = if input.is_absolute() {
            input.clone()
        } else {
            cwd.join(input)
        };

        let meta = fs::metadata(&abs)?;
        let kind = if meta.is_file() {
            InputKind::File
        } else if meta.is_dir() {
            InputKind::Dir
        } else {
            return Err(NoerError::InvalidFormat(format!(
                "invalid input: {}",
                abs.display()
            )));
        };

        let base_name = abs
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("input{}", idx + 1));
        *base_counts.entry(base_name.clone()).or_insert(0) += 1;

        specs.push(InputSpec {
            abs_path: abs,
            kind,
            base_name,
        });
    }

    let mut entries = Vec::new();
    let mut seen = RelPathSet::default();
    let mut name_positions = HashMap::<String, usize>::new();

    for spec in specs {
        let ordinal = {
            let slot = name_positions.entry(spec.base_name.clone()).or_insert(0);
            *slot += 1;
            *slot
        };
        let repeated = base_counts.get(&spec.base_name).copied().unwrap_or(0) > 1;

        match spec.kind {
            InputKind::File => {
                let rel = if repeated {
                    disambiguate_name(&spec.base_name, ordinal, true)
                } else {
                    spec.base_name.clone()
                };
                push_entry(&spec.abs_path, rel, false, &mut entries, &mut seen)?;
            }
            InputKind::Dir => {
                let root_name = if repeated {
                    disambiguate_name(&spec.base_name, ordinal, false)
                } else {
                    spec.base_name.clone()
                };

                // Preserve the root folder itself, allowing archives of empty directories.
                push_entry(
                    &spec.abs_path,
                    root_name.clone(),
                    true,
                    &mut entries,
                    &mut seen,
                )?;

                for item in WalkDir::new(&spec.abs_path)
                    .min_depth(1)
                    .follow_links(false)
                {
                    let item = item.map_err(|e| NoerError::InvalidFormat(e.to_string()))?;
                    let rel_inside = item
                        .path()
                        .strip_prefix(&spec.abs_path)
                        .map_err(|_| NoerError::InvalidFormat("invalid relative path".into()))?;
                    let rel_inside = normalized_rel_string(rel_inside)?;
                    let rel = format!("{root_name}/{rel_inside}");

                    if item.file_type().is_dir() {
                        push_entry(item.path(), rel, true, &mut entries, &mut seen)?;
                    } else if item.file_type().is_file() {
                        push_entry(item.path(), rel, false, &mut entries, &mut seen)?;
                    }
                }
            }
        }
    }

    Ok(entries)
}

fn push_entry(
    path: &Path,
    rel_path: String,
    is_dir: bool,
    entries: &mut Vec<SourceEntry>,
    seen: &mut RelPathSet,
) -> Result<()> {
    let rel_path = normalized_rel_string(Path::new(&rel_path))?;
    seen.insert(&rel_path, is_dir)?;

    let meta = fs::metadata(path)?;
    let size = if is_dir { 0 } else { meta.len() };
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mode = file_mode(&meta);

    entries.push(SourceEntry {
        abs_path: Some(path.to_path_buf()),
        meta: FileEntry {
            path: rel_path,
            size,
            modified,
            mode,
            is_dir,
            deleted: false,
        },
    });
    Ok(())
}

fn normalized_rel_string(path: &Path) -> Result<String> {
    let as_str = path.to_string_lossy();
    let sanitized = utils::sanitize_rel_path(&as_str)?;
    Ok(sanitized.to_string_lossy().replace('\\', "/"))
}

fn disambiguate_name(name: &str, ordinal: usize, is_file: bool) -> String {
    if !is_file {
        return format!("{name}_{ordinal}");
    }

    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = path.extension().and_then(|s| s.to_str());
    match ext {
        Some(ext) if !ext.is_empty() => format!("{stem}_{ordinal}.{ext}"),
        _ => format!("{name}_{ordinal}"),
    }
}

fn estimate_archive_size(total_input: u64, meta_len: u64, level: i32) -> u64 {
    let ratio = if level <= 0 {
        0.95
    } else if level <= 5 {
        0.70
    } else if level <= 10 {
        0.58
    } else if level <= 15 {
        0.48
    } else {
        0.40
    };
    let comp = (total_input as f64 * ratio) as u64;
    comp + meta_len + 64 + 1024
}

fn apply_incremental_filter(
    entries: Vec<SourceEntry>,
    previous: &incremental::IncrementalIndex,
) -> Result<(
    Vec<SourceEntry>,
    incremental::IncrementalIndex,
    incremental::IncrementalStats,
    bool,
    usize,
)> {
    let probes: Vec<FileProbe> = entries
        .iter()
        .filter(|e| !e.meta.is_dir && !e.meta.deleted)
        .map(|entry| {
            let abs = entry.abs_path.as_ref().ok_or_else(|| {
                NoerError::InvalidFormat("missing source path in incremental scan".into())
            })?;
            Ok(FileProbe {
                rel_path: entry.meta.path.clone(),
                abs_path: abs.clone(),
                size: entry.meta.size,
                modified: entry.meta.modified,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let had_input_files = !probes.is_empty();
    let (next_index, changed_files, stats) = incremental::evaluate(&probes, previous)?;

    let current_paths: HashSet<String> = entries.iter().map(|e| e.meta.path.clone()).collect();
    let mut removed_paths: Vec<String> = previous
        .files
        .keys()
        .filter(|old| !next_index.files.contains_key(*old) && !current_paths.contains(*old))
        .cloned()
        .collect();
    removed_paths.sort();

    let mut keep_dirs = HashSet::new();
    for file_path in &changed_files {
        for parent in parent_directories(file_path) {
            keep_dirs.insert(parent);
        }
    }

    let mut filtered: Vec<SourceEntry> = entries
        .into_iter()
        .filter(|entry| {
            if entry.meta.is_dir {
                keep_dirs.contains(&entry.meta.path)
            } else {
                changed_files.contains(&entry.meta.path)
            }
        })
        .collect();

    for path in &removed_paths {
        filtered.push(SourceEntry {
            abs_path: None,
            meta: FileEntry {
                path: path.clone(),
                size: 0,
                modified: 0,
                mode: 0,
                is_dir: false,
                deleted: true,
            },
        });
    }

    filtered.sort_by(|a, b| a.meta.path.cmp(&b.meta.path));

    Ok((
        filtered,
        next_index,
        stats,
        had_input_files,
        removed_paths.len(),
    ))
}

fn parent_directories(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = path;
    while let Some((parent, _)) = cursor.rsplit_once('/') {
        out.push(parent.to_string());
        cursor = parent;
    }
    out
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_meta: &fs::Metadata) -> u32 {
    0
}

impl From<CipherChoice> for CryptoAlgo {
    fn from(value: CipherChoice) -> Self {
        match value {
            CipherChoice::ChaCha20Poly1305 => CryptoAlgo::ChaCha20Poly1305,
            CipherChoice::Aes256Gcm => CryptoAlgo::Aes256Gcm,
        }
    }
}

impl From<ChecksumChoice> for ChecksumAlgo {
    fn from(value: ChecksumChoice) -> Self {
        match value {
            ChecksumChoice::Sha256 => ChecksumAlgo::Sha256,
            ChecksumChoice::Blake3 => ChecksumAlgo::Blake3,
        }
    }
}
