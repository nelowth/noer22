use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metadata {
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub modified: u64,
    pub mode: u32,
    #[serde(default)]
    pub is_dir: bool,
}

pub fn serialize(metadata: &Metadata) -> Result<Vec<u8>> {
    Ok(postcard::to_stdvec(metadata)?)
}

pub fn deserialize(bytes: &[u8]) -> Result<Metadata> {
    Ok(postcard::from_bytes(bytes)?)
}
