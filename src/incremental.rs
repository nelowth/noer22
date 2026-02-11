use crate::error::{NoerError, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const INDEX_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFingerprint {
    pub size: u64,
    pub modified: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalIndex {
    pub version: u16,
    pub files: HashMap<String, FileFingerprint>,
}

impl Default for IncrementalIndex {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            files: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileProbe {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub size: u64,
    pub modified: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IncrementalStats {
    pub previous_files: usize,
    pub scanned_files: usize,
    pub changed_files: usize,
    pub skipped_files: usize,
    pub removed_files: usize,
}

pub fn load_or_default(path: &Path) -> Result<IncrementalIndex> {
    if !path.exists() {
        return Ok(IncrementalIndex::default());
    }
    let raw = fs::read_to_string(path)?;
    let parsed: IncrementalIndex = serde_json::from_str(&raw)
        .map_err(|e| NoerError::InvalidFormat(format!("invalid incremental index: {e}")))?;
    Ok(parsed)
}

pub fn save(path: &Path, index: &IncrementalIndex) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let raw = serde_json::to_string_pretty(index)
        .map_err(|e| NoerError::InvalidFormat(format!("failed to serialize index: {e}")))?;
    fs::write(path, raw)?;
    Ok(())
}

pub fn evaluate(
    probes: &[FileProbe],
    previous: &IncrementalIndex,
) -> Result<(IncrementalIndex, HashSet<String>, IncrementalStats)> {
    let computed: Vec<Result<(String, FileFingerprint)>> = probes
        .par_iter()
        .map(|probe| {
            let digest = hash_file_blake3(&probe.abs_path)?;
            Ok((
                probe.rel_path.clone(),
                FileFingerprint {
                    size: probe.size,
                    modified: probe.modified,
                    blake3: digest,
                },
            ))
        })
        .collect();

    let mut files = HashMap::with_capacity(probes.len());
    let mut changed = HashSet::new();

    for item in computed {
        let (rel, fp) = item?;
        let is_changed = previous
            .files
            .get(&rel)
            .map(|old| old != &fp)
            .unwrap_or(true);
        if is_changed {
            changed.insert(rel.clone());
        }
        files.insert(rel, fp);
    }

    let removed_files = previous
        .files
        .keys()
        .filter(|old| !files.contains_key(*old))
        .count();

    let stats = IncrementalStats {
        previous_files: previous.files.len(),
        scanned_files: probes.len(),
        changed_files: changed.len(),
        skipped_files: probes.len().saturating_sub(changed.len()),
        removed_files,
    };

    Ok((
        IncrementalIndex {
            version: INDEX_VERSION,
            files,
        },
        changed,
        stats,
    ))
}

fn hash_file_blake3(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}
