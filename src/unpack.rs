use crate::cli::{ListArgs, UnpackArgs, VerifyArgs};
use crate::crypto::{self, DecryptReader};
use crate::error::{NoerError, Result};
use crate::format::{CryptoAlgo, Header, HEADER_SIZE, VERSION};
use crate::metadata::{self, FileEntry, Metadata};
use crate::utils;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct ArchiveOverview {
    pub version: u16,
    pub crypto_name: String,
    pub kdf_mem_mib: u32,
    pub kdf_iters: u32,
    pub kdf_parallelism: u32,
    pub total_entries: usize,
    pub file_count: usize,
    pub dir_count: usize,
    pub total_bytes: u64,
    pub entries: Vec<FileEntry>,
}

pub fn unpack(args: UnpackArgs) -> Result<()> {
    let opened = open_archive(&args.archive, &args.password)?;

    let out_dir = match args.output {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };
    std::fs::create_dir_all(&out_dir)?;

    let total_size: u64 = opened.metadata.files.iter().map(|f| f.size).sum();
    let pb = utils::progress_bar(total_size, "extracting");

    let decrypt_reader = DecryptReader::new(opened.reader, opened.decryptor);
    let mut decoder = zstd::stream::Decoder::new(decrypt_reader)
        .map_err(|e| NoerError::InvalidFormat(e.to_string()))?;
    let _ = decoder.window_log_max(31);

    for entry in opened.metadata.files {
        let rel = utils::sanitize_rel_path(&entry.path)?;
        let out_path: PathBuf = out_dir.join(rel);
        if entry.is_dir {
            std::fs::create_dir_all(&out_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(entry.mode);
                let _ = std::fs::set_permissions(&out_path, perms);
            }
            continue;
        }

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out_file = File::create(&out_path)?;
        if let Err(err) = utils::copy_exact(&mut decoder, &mut out_file, entry.size, &pb) {
            if is_auth_error(&err) {
                return Err(NoerError::AuthenticationFailed);
            }
            return Err(NoerError::Io(err));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(entry.mode);
            let _ = std::fs::set_permissions(&out_path, perms);
        }
    }

    ensure_decoder_drained(&mut decoder)?;

    pb.finish_and_clear();
    Ok(())
}

pub fn inspect_archive(path: &Path, password: &str) -> Result<ArchiveOverview> {
    let opened = open_archive(path, password)?;
    Ok(build_overview(&opened.header, &opened.metadata))
}

pub fn list(args: ListArgs) -> Result<()> {
    let overview = inspect_archive(&args.archive, &args.password)?;

    println!("Archive: {}", args.archive.display());
    println!("Version: {}", overview.version);
    println!("Cipher: {}", overview.crypto_name);
    println!(
        "KDF Argon2id: mem={} MiB, iters={}, parallel={}",
        overview.kdf_mem_mib, overview.kdf_iters, overview.kdf_parallelism
    );
    println!(
        "Entries: {} ({} files, {} directories)",
        overview.total_entries, overview.file_count, overview.dir_count
    );
    println!("Payload size: {}", utils::human_bytes(overview.total_bytes));
    println!();

    if args.long {
        println!("TYPE  SIZE         MODIFIED    MODE   PATH");
        for entry in &overview.entries {
            let kind = if entry.is_dir { "dir " } else { "file" };
            let size = if entry.is_dir {
                "-".to_string()
            } else {
                utils::human_bytes(entry.size)
            };
            println!(
                "{kind:<4}  {size:<11}  {:<10}  {:>04o}  {}",
                entry.modified, entry.mode, entry.path
            );
        }
    } else {
        for entry in &overview.entries {
            if entry.is_dir {
                println!("[DIR]  {}", entry.path);
            } else {
                println!("[FILE] {} ({})", entry.path, utils::human_bytes(entry.size));
            }
        }
    }

    Ok(())
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    let opened = open_archive(&args.archive, &args.password)?;

    let total_size: u64 = opened
        .metadata
        .files
        .iter()
        .filter(|f| !f.is_dir)
        .map(|f| f.size)
        .sum();
    let pb = utils::progress_bar(total_size, "verifying");

    let decrypt_reader = DecryptReader::new(opened.reader, opened.decryptor);
    let mut decoder = zstd::stream::Decoder::new(decrypt_reader)
        .map_err(|e| NoerError::InvalidFormat(e.to_string()))?;
    let _ = decoder.window_log_max(31);

    let mut sink = std::io::sink();
    for entry in opened.metadata.files {
        if entry.is_dir {
            continue;
        }
        if let Err(err) = utils::copy_exact(&mut decoder, &mut sink, entry.size, &pb) {
            if is_auth_error(&err) {
                return Err(NoerError::AuthenticationFailed);
            }
            return Err(NoerError::Io(err));
        }
    }

    ensure_decoder_drained(&mut decoder)?;

    pb.finish_and_clear();
    println!("Verification complete: integrity OK");
    Ok(())
}

struct OpenArchive {
    header: Header,
    metadata: Metadata,
    reader: BufReader<File>,
    decryptor: crypto::ChunkDecryptor,
}

fn open_archive(path: &Path, password: &str) -> Result<OpenArchive> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut header_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_bytes)?;
    let header = Header::from_bytes(header_bytes)?;

    let password = Zeroizing::new(password.to_string());
    let key = crypto::derive_key(password.as_ref(), &header.salt, header.kdf)?;
    let mut decryptor = crypto::ChunkDecryptor::new(
        header.crypto,
        key.as_ref(),
        header.nonce,
        header_bytes.to_vec(),
    )?;

    let meta_bytes = decryptor
        .decrypt_chunk(&mut reader)?
        .ok_or_else(|| NoerError::InvalidFormat("missing metadata chunk".into()))?;
    let metadata = metadata::deserialize(&meta_bytes)?;
    validate_metadata_paths(&metadata)?;

    Ok(OpenArchive {
        header,
        metadata,
        reader,
        decryptor,
    })
}

fn build_overview(header: &Header, metadata: &Metadata) -> ArchiveOverview {
    let file_count = metadata.files.iter().filter(|f| !f.is_dir).count();
    let dir_count = metadata.files.iter().filter(|f| f.is_dir).count();
    let total_bytes = metadata
        .files
        .iter()
        .filter(|f| !f.is_dir)
        .map(|f| f.size)
        .sum();

    ArchiveOverview {
        version: VERSION,
        crypto_name: crypto_name(header.crypto).to_string(),
        kdf_mem_mib: header.kdf.mem_kib / 1024,
        kdf_iters: header.kdf.iterations,
        kdf_parallelism: header.kdf.parallelism,
        total_entries: metadata.files.len(),
        file_count,
        dir_count,
        total_bytes,
        entries: metadata.files.clone(),
    }
}

fn validate_metadata_paths(metadata: &Metadata) -> Result<()> {
    let mut seen = utils::RelPathSet::default();
    for entry in &metadata.files {
        seen.insert(&entry.path, entry.is_dir)?;
    }
    Ok(())
}

fn ensure_decoder_drained<R: BufRead>(decoder: &mut zstd::stream::Decoder<'_, R>) -> Result<()> {
    let mut probe = [0u8; 1];
    match decoder.read(&mut probe) {
        Ok(0) => Ok(()),
        Ok(_) => Err(NoerError::InvalidFormat(
            "extra trailing data in archive".into(),
        )),
        Err(err) => {
            if is_auth_error(&err) {
                Err(NoerError::AuthenticationFailed)
            } else {
                Err(NoerError::InvalidFormat(err.to_string()))
            }
        }
    }
}

fn is_auth_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidData
        && err.to_string().contains(crypto::AUTH_ERROR_TAG)
}

fn crypto_name(crypto: CryptoAlgo) -> &'static str {
    match crypto {
        CryptoAlgo::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        CryptoAlgo::Aes256Gcm => "AES-256-GCM",
    }
}
