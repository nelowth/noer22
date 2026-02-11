use crate::cli::{CipherChoice, PackArgs};
use crate::compression;
use crate::crypto::{self, EncryptWriter};
use crate::error::{NoerError, Result};
use crate::format::{CompressionAlgo, CryptoAlgo, Header, KdfParams};
use crate::metadata::{self, FileEntry, Metadata};
use crate::utils::{self, ConcatReader, ProgressReader, RelPathSet};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;
use zeroize::Zeroizing;

pub fn pack(args: PackArgs) -> Result<()> {
    if args.inputs.is_empty() {
        return Err(NoerError::InvalidFormat("no input provided".into()));
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

    let total_size: u64 = entries
        .iter()
        .filter(|e| !e.meta.is_dir)
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
    let header = Header::new(CompressionAlgo::Zstd, args.cipher.into(), salt, nonce, kdf);
    let header_bytes = header.to_bytes();

    let password = Zeroizing::new(args.password);
    let key = crypto::derive_key(password.as_ref(), &salt, kdf)?;
    let mut encryptor =
        crypto::ChunkEncryptor::new(header.crypto, key.as_ref(), nonce, header_bytes.to_vec())?;

    let out_file = File::create(&args.output)?;
    let mut writer = BufWriter::new(out_file);
    writer.write_all(&header_bytes)?;
    encryptor.encrypt_chunk(&meta_bytes, &mut writer)?;

    let paths: Vec<PathBuf> = entries
        .iter()
        .filter(|e| !e.meta.is_dir)
        .map(|e| e.abs_path.clone())
        .collect();
    let concat = ConcatReader::new(paths);
    let pb = utils::progress_bar(total_size, "packing");
    let mut reader = ProgressReader::new(concat, pb.clone());

    let encrypt_writer = EncryptWriter::new(writer, encryptor);
    let threads = args.threads.unwrap_or_else(utils::default_threads);
    let encrypt_writer = compression::compress_reader_to_writer(
        &mut reader,
        encrypt_writer,
        args.level,
        threads,
        Some(total_size),
    )?;
    let mut writer = encrypt_writer.finish()?;
    writer.flush()?;
    pb.finish_and_clear();

    Ok(())
}

struct SourceEntry {
    abs_path: PathBuf,
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
        abs_path: path.to_path_buf(),
        meta: FileEntry {
            path: rel_path,
            size,
            modified,
            mode,
            is_dir,
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
