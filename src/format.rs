use crate::error::{NoerError, Result};

pub const MAGIC: &[u8; 8] = b"NOER22\0\0";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 64;

#[derive(Debug, Clone, Copy)]
pub enum CompressionAlgo {
    Zstd = 0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgo {
    ChaCha20Poly1305 = 0,
    Aes256Gcm = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub compression: CompressionAlgo,
    pub crypto: CryptoAlgo,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub kdf: KdfParams,
}

impl Header {
    pub fn new(
        compression: CompressionAlgo,
        crypto: CryptoAlgo,
        salt: [u8; 16],
        nonce: [u8; 12],
        kdf: KdfParams,
    ) -> Self {
        Self {
            compression,
            crypto,
            salt,
            nonce,
            kdf,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..10].copy_from_slice(&VERSION.to_le_bytes());
        buf[10] = self.compression as u8;
        buf[11] = self.crypto as u8;
        buf[12..28].copy_from_slice(&self.salt);
        buf[28..40].copy_from_slice(&self.nonce);
        buf[40..44].copy_from_slice(&self.kdf.mem_kib.to_le_bytes());
        buf[44..48].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        buf[48..52].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: [u8; HEADER_SIZE]) -> Result<Self> {
        if &bytes[0..8] != MAGIC {
            return Err(NoerError::InvalidFormat("invalid magic".into()));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        if version != VERSION {
            return Err(NoerError::InvalidFormat(format!(
                "unsupported version: {version}"
            )));
        }
        let compression = match bytes[10] {
            0 => CompressionAlgo::Zstd,
            _ => return Err(NoerError::UnsupportedAlgorithm),
        };
        let crypto = match bytes[11] {
            0 => CryptoAlgo::ChaCha20Poly1305,
            1 => CryptoAlgo::Aes256Gcm,
            _ => return Err(NoerError::UnsupportedAlgorithm),
        };
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[12..28]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[28..40]);
        let mem_kib = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let iterations = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        let parallelism = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        let kdf = if mem_kib == 0 || iterations == 0 || parallelism == 0 {
            KdfParams::default()
        } else {
            KdfParams {
                mem_kib,
                iterations,
                parallelism,
            }
        };

        Ok(Header {
            compression,
            crypto,
            salt,
            nonce,
            kdf,
        })
    }
}
