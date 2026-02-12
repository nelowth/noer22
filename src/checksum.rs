use crate::error::{NoerError, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgo {
    Sha256,
    Blake3,
}

impl ChecksumAlgo {
    pub fn id(self) -> &'static str {
        match self {
            ChecksumAlgo::Sha256 => "sha256",
            ChecksumAlgo::Blake3 => "blake3",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sha256" => Some(ChecksumAlgo::Sha256),
            "blake3" => Some(ChecksumAlgo::Blake3),
            _ => None,
        }
    }
}

pub struct ChecksumVerification {
    pub algo: ChecksumAlgo,
    pub expected: String,
    pub actual: String,
}

pub fn default_sidecar_path(archive: &Path, algo: ChecksumAlgo) -> PathBuf {
    let mut raw = archive.as_os_str().to_os_string();
    raw.push(format!(".{}", algo.id()));
    PathBuf::from(raw)
}

pub fn hash_file(path: &Path, algo: ChecksumAlgo) -> Result<String> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 1024 * 1024];

    match algo {
        ChecksumAlgo::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex_encode(&hasher.finalize()))
        }
        ChecksumAlgo::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
    }
}

pub fn write_sidecar(archive: &Path, algo: ChecksumAlgo, output: Option<&Path>) -> Result<PathBuf> {
    let digest = hash_file(archive, algo)?;
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_sidecar_path(archive, algo));
    if out_path.exists() {
        return Err(NoerError::InvalidFormat(format!(
            "checksum output already exists: {}",
            out_path.display()
        )));
    }
    let archive_name = archive
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| archive.display().to_string());

    let mut file = File::create(&out_path)?;
    writeln!(file, "{}:{}  {}", algo.id(), digest, archive_name)?;
    Ok(out_path)
}

pub fn verify_sidecar(
    archive: &Path,
    sidecar: &Path,
    forced_algo: Option<ChecksumAlgo>,
) -> Result<ChecksumVerification> {
    let file = File::open(sidecar)?;
    let mut line = String::new();
    let mut reader = BufReader::new(file);
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(NoerError::InvalidFormat("empty checksum file".into()));
    }

    let token = line
        .split_whitespace()
        .next()
        .ok_or_else(|| NoerError::InvalidFormat("invalid checksum file".into()))?;

    let (algo_in_file, expected) = if let Some((algo, value)) = token.split_once(':') {
        let parsed = ChecksumAlgo::parse(algo).ok_or_else(|| {
            NoerError::InvalidFormat(format!("unsupported checksum algorithm in sidecar: {algo}"))
        })?;
        (Some(parsed), value.to_string())
    } else {
        (None, token.to_string())
    };

    let algo = match (forced_algo, algo_in_file) {
        (Some(forced), Some(from_file)) if forced != from_file => {
            return Err(NoerError::InvalidFormat(format!(
                "checksum algorithm mismatch: CLI={}, sidecar={}",
                forced.id(),
                from_file.id()
            )))
        }
        (Some(forced), _) => forced,
        (None, Some(from_file)) => from_file,
        (None, None) => {
            return Err(NoerError::InvalidFormat(
                "checksum algorithm missing; use --checksum-algo".into(),
            ))
        }
    };

    if !is_hex_64(&expected) {
        return Err(NoerError::InvalidFormat(
            "invalid checksum hex in sidecar".into(),
        ));
    }

    let actual = hash_file(archive, algo)?;
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(NoerError::InvalidFormat(format!(
            "checksum mismatch (expected {}, got {})",
            expected, actual
        )));
    }

    Ok(ChecksumVerification {
        algo,
        expected,
        actual,
    })
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_digit((b >> 4) & 0x0f));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '0',
    }
}
