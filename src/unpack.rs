use crate::agewrap;
use crate::checksum::{self, ChecksumAlgo};
use crate::cli::{ChecksumChoice, ListArgs, UnpackArgs, VerifyArgs};
use crate::crypto::{self, DecryptReader};
use crate::error::{NoerError, Result};
use crate::format::{CryptoAlgo, Header, HEADER_SIZE, VERSION};
use crate::metadata::{self, FileEntry, Metadata};
use crate::utils;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_AGE_ENVELOPE_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ArchiveOverview {
    pub version: u16,
    pub crypto_name: String,
    pub kdf_mem_mib: u32,
    pub kdf_iters: u32,
    pub kdf_parallelism: u32,
    pub keyfile_required: bool,
    pub incremental_archive: bool,
    pub age_recipients_archive: bool,
    pub total_entries: usize,
    pub file_count: usize,
    pub dir_count: usize,
    pub deleted_count: usize,
    pub total_bytes: u64,
    pub entries: Vec<FileEntry>,
}

pub fn unpack(args: UnpackArgs) -> Result<()> {
    if let Some(checksum_file) = args.checksum_file.as_ref() {
        let result = checksum::verify_sidecar(
            &args.archive,
            checksum_file,
            args.checksum_algo.map(checksum_choice_to_algo),
        )?;
        println!("External checksum OK ({})", result.algo.id());
    }

    let opened = open_archive(
        &args.archive,
        args.password.as_deref(),
        args.keyfile.as_deref(),
        &args.age_identities,
    )?;

    let out_dir = match args.output {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };
    std::fs::create_dir_all(&out_dir)?;

    let total_size: u64 = opened
        .metadata
        .files
        .iter()
        .filter(|f| !f.is_dir && !f.deleted)
        .map(|f| f.size)
        .sum();
    let pb = utils::progress_bar(total_size, "extracting");

    let decrypt_reader = DecryptReader::new(opened.reader, opened.decryptor);
    let mut decoder = zstd::stream::Decoder::new(decrypt_reader)
        .map_err(|e| NoerError::InvalidFormat(e.to_string()))?;
    let _ = decoder.window_log_max(31);

    for entry in opened.metadata.files {
        let rel = utils::sanitize_rel_path(&entry.path)?;
        let out_path: PathBuf = out_dir.join(rel);
        if entry.deleted {
            remove_existing_path(&out_path)?;
            continue;
        }
        if entry.is_dir {
            ensure_directory_path(&out_path)?;
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
            ensure_directory_path(parent)?;
            std::fs::create_dir_all(parent)?;
        }
        if out_path.is_dir() {
            std::fs::remove_dir_all(&out_path)?;
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
    inspect_archive_with_auth(path, Some(password), None, &[])
}

pub fn inspect_archive_with_auth(
    path: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
    age_identities: &[PathBuf],
) -> Result<ArchiveOverview> {
    let opened = open_archive(path, password, keyfile, age_identities)?;
    Ok(build_overview(&opened.header, &opened.metadata))
}

pub fn list(args: ListArgs) -> Result<()> {
    let opened = open_archive(
        &args.archive,
        args.password.as_deref(),
        args.keyfile.as_deref(),
        &args.age_identities,
    )?;
    let overview = build_overview(&opened.header, &opened.metadata);

    println!("Archive: {}", args.archive.display());
    println!("Version: {}", overview.version);
    println!("Cipher: {}", overview.crypto_name);
    println!(
        "KDF Argon2id: mem={} MiB, iters={}, parallel={}",
        overview.kdf_mem_mib, overview.kdf_iters, overview.kdf_parallelism
    );
    let auth_mode = if overview.age_recipients_archive {
        "age recipients"
    } else if overview.keyfile_required {
        "password + keyfile / keyfile-only"
    } else {
        "password"
    };
    println!("Auth material: {auth_mode}");
    println!(
        "Archive mode: {}",
        if overview.incremental_archive {
            "incremental"
        } else {
            "full"
        }
    );
    println!(
        "Entries: {} ({} files, {} directories, {} deletions)",
        overview.total_entries, overview.file_count, overview.dir_count, overview.deleted_count
    );
    println!("Payload size: {}", utils::human_bytes(overview.total_bytes));
    println!();

    if args.long {
        println!("TYPE  SIZE         MODIFIED    MODE   PATH");
        for entry in &overview.entries {
            let kind = if entry.deleted {
                "del "
            } else if entry.is_dir {
                "dir "
            } else {
                "file"
            };
            let size = if entry.is_dir || entry.deleted {
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
            if entry.deleted {
                println!("[DEL]  {}", entry.path);
            } else if entry.is_dir {
                println!("[DIR]  {}", entry.path);
            } else {
                println!("[FILE] {} ({})", entry.path, utils::human_bytes(entry.size));
            }
        }
    }

    Ok(())
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    let mut verified_any = false;

    if let Some(checksum_file) = args.checksum_file.as_ref() {
        let result = checksum::verify_sidecar(
            &args.archive,
            checksum_file,
            args.checksum_algo.map(checksum_choice_to_algo),
        )?;
        println!("External checksum OK ({})", result.algo.id());
        verified_any = true;
    }

    if args.password.is_some() || args.keyfile.is_some() || !args.age_identities.is_empty() {
        verify_archive_payload(
            &args.archive,
            args.password.as_deref(),
            args.keyfile.as_deref(),
            &args.age_identities,
        )?;
        println!("Payload verification OK");
        verified_any = true;
    }

    if !verified_any {
        return Err(NoerError::InvalidFormat(
            "provide auth credentials/age identity or --checksum-file".into(),
        ));
    }

    println!("Verification complete: integrity OK");
    Ok(())
}

fn verify_archive_payload(
    path: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
    age_identities: &[PathBuf],
) -> Result<()> {
    let opened = open_archive(path, password, keyfile, age_identities)?;

    let total_size: u64 = opened
        .metadata
        .files
        .iter()
        .filter(|f| !f.is_dir && !f.deleted)
        .map(|f| f.size)
        .sum();
    let pb = utils::progress_bar(total_size, "verifying");

    let decrypt_reader = DecryptReader::new(opened.reader, opened.decryptor);
    let mut decoder = zstd::stream::Decoder::new(decrypt_reader)
        .map_err(|e| NoerError::InvalidFormat(e.to_string()))?;
    let _ = decoder.window_log_max(31);

    let mut sink = std::io::sink();
    for entry in opened.metadata.files {
        if entry.is_dir || entry.deleted {
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
    Ok(())
}

struct OpenArchive {
    header: Header,
    metadata: Metadata,
    reader: BufReader<File>,
    decryptor: crypto::ChunkDecryptor,
}

fn open_archive(
    path: &Path,
    password: Option<&str>,
    keyfile_path: Option<&Path>,
    age_identities: &[PathBuf],
) -> Result<OpenArchive> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut header_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_bytes)?;
    let header = Header::from_bytes(header_bytes)?;

    let key = if header.flags.age_recipients {
        let envelope = read_age_envelope(&mut reader)?;
        agewrap::decrypt_file_key(&envelope, age_identities)?
    } else {
        let keyfile = keyfile_path.map(crypto::read_keyfile).transpose()?;
        if header.flags.keyfile_required && keyfile.is_none() {
            return Err(NoerError::InvalidFormat(
                "archive requires keyfile; provide --keyfile <path>".into(),
            ));
        }

        let password = password.map(|p| Zeroizing::new(p.to_string()));
        let password_ref = password.as_deref().map(|s| s.as_str());
        crypto::derive_key_material(
            password_ref,
            keyfile.as_deref().map(|v| v.as_slice()),
            &header.salt,
            header.kdf,
        )?
    };

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

fn read_age_envelope<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGE_ENVELOPE_LEN {
        return Err(NoerError::InvalidFormat(
            "invalid age envelope length".into(),
        ));
    }
    let mut envelope = vec![0u8; len];
    reader.read_exact(&mut envelope)?;
    Ok(envelope)
}

fn build_overview(header: &Header, metadata: &Metadata) -> ArchiveOverview {
    let file_count = metadata
        .files
        .iter()
        .filter(|f| !f.is_dir && !f.deleted)
        .count();
    let dir_count = metadata.files.iter().filter(|f| f.is_dir).count();
    let deleted_count = metadata.files.iter().filter(|f| f.deleted).count();
    let total_bytes = metadata
        .files
        .iter()
        .filter(|f| !f.is_dir && !f.deleted)
        .map(|f| f.size)
        .sum();

    ArchiveOverview {
        version: VERSION,
        crypto_name: crypto_name(header.crypto).to_string(),
        kdf_mem_mib: header.kdf.mem_kib / 1024,
        kdf_iters: header.kdf.iterations,
        kdf_parallelism: header.kdf.parallelism,
        keyfile_required: header.flags.keyfile_required,
        incremental_archive: header.flags.incremental,
        age_recipients_archive: header.flags.age_recipients,
        total_entries: metadata.files.len(),
        file_count,
        dir_count,
        deleted_count,
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

fn checksum_choice_to_algo(choice: ChecksumChoice) -> ChecksumAlgo {
    match choice {
        ChecksumChoice::Sha256 => ChecksumAlgo::Sha256,
        ChecksumChoice::Blake3 => ChecksumAlgo::Blake3,
    }
}

fn remove_existing_path(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(NoerError::Io(err)),
    };

    if meta.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn ensure_directory_path(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(NoerError::Io(err)),
    };

    if !meta.is_dir() {
        remove_existing_path(path)?;
    }
    Ok(())
}
