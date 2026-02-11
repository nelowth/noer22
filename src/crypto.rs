use crate::error::{NoerError, Result};
use crate::format::{CryptoAlgo, KdfParams};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub const TAG_LEN: usize = 16;
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const AUTH_ERROR_TAG: &str = "NOER22_AUTH_FAILED";

pub fn random_salt() -> Result<[u8; 16]> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)
        .map_err(|_| NoerError::InvalidFormat("failed to generate salt".into()))?;
    Ok(salt)
}

pub fn random_nonce() -> Result<[u8; 12]> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)
        .map_err(|_| NoerError::InvalidFormat("failed to generate nonce".into()))?;
    nonce[8..12].copy_from_slice(&0u32.to_be_bytes());
    Ok(nonce)
}

pub fn derive_key(
    password: &str,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let argon_params = Params::new(
        params.mem_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password.as_bytes(), salt, key.as_mut())?;
    Ok(key)
}

fn algo_to_ring(algo: CryptoAlgo) -> Result<&'static aead::Algorithm> {
    match algo {
        CryptoAlgo::ChaCha20Poly1305 => Ok(&aead::CHACHA20_POLY1305),
        CryptoAlgo::Aes256Gcm => Ok(&aead::AES_256_GCM),
    }
}

#[derive(Clone)]
struct NonceCounter {
    prefix: [u8; 8],
    counter: u32,
}

impl NonceCounter {
    fn new(nonce: [u8; 12]) -> Self {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&nonce[0..8]);
        let counter = u32::from_be_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
        Self { prefix, counter }
    }

    fn next(&mut self) -> Result<Nonce> {
        if self.counter == u32::MAX {
            return Err(NoerError::InvalidFormat(
                "contador de nonce excedido".into(),
            ));
        }
        let ctr = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| NoerError::InvalidFormat("contador de nonce excedido".into()))?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&self.prefix);
        nonce_bytes[8..12].copy_from_slice(&ctr.to_be_bytes());
        Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| NoerError::InvalidFormat("invalid nonce".into()))
    }
}

pub struct ChunkEncryptor {
    key: LessSafeKey,
    nonce: NonceCounter,
    aad: Vec<u8>,
}

impl ChunkEncryptor {
    pub fn new(algo: CryptoAlgo, key: &[u8], nonce: [u8; 12], aad: Vec<u8>) -> Result<Self> {
        let unbound = UnboundKey::new(algo_to_ring(algo)?, key)
            .map_err(|_| NoerError::InvalidFormat("chave invalida".into()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce: NonceCounter::new(nonce),
            aad,
        })
    }

    pub fn encrypt_chunk<W: Write>(&mut self, plaintext: &[u8], writer: &mut W) -> Result<()> {
        let mut buf = plaintext.to_vec();
        self.encrypt_chunk_owned(&mut buf, writer)
    }

    pub fn encrypt_chunk_owned<W: Write>(
        &mut self,
        plaintext: &mut [u8],
        writer: &mut W,
    ) -> Result<()> {
        let nonce = self.nonce.next()?;
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&self.aad), plaintext)
            .map_err(|_| NoerError::InvalidFormat("encryption failed".into()))?;
        let total_len = plaintext.len() + TAG_LEN;
        if total_len > u32::MAX as usize {
            return Err(NoerError::InvalidFormat("chunk grande demais".into()));
        }
        writer.write_all(&(total_len as u32).to_le_bytes())?;
        writer.write_all(plaintext)?;
        writer.write_all(tag.as_ref())?;
        Ok(())
    }
}

pub struct ChunkDecryptor {
    key: LessSafeKey,
    nonce: NonceCounter,
    aad: Vec<u8>,
}

impl ChunkDecryptor {
    pub fn new(algo: CryptoAlgo, key: &[u8], nonce: [u8; 12], aad: Vec<u8>) -> Result<Self> {
        let unbound = UnboundKey::new(algo_to_ring(algo)?, key)
            .map_err(|_| NoerError::InvalidFormat("chave invalida".into()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce: NonceCounter::new(nonce),
            aad,
        })
    }

    pub fn decrypt_chunk<R: Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        let first_read = reader.read(&mut len_buf)?;
        if first_read == 0 {
            return Ok(None);
        }
        if first_read < len_buf.len() {
            reader
                .read_exact(&mut len_buf[first_read..])
                .map_err(|_| NoerError::InvalidFormat("truncated archive".into()))?;
        }
        let total_len = u32::from_le_bytes(len_buf) as usize;
        if total_len < TAG_LEN {
            return Err(NoerError::InvalidFormat("invalid chunk".into()));
        }
        let mut buf = vec![0u8; total_len];
        reader.read_exact(&mut buf)?;
        let ct_len = total_len - TAG_LEN;
        let (ciphertext, tag_bytes) = buf.split_at_mut(ct_len);
        let tag: aead::Tag = (&*tag_bytes)
            .try_into()
            .map_err(|_| NoerError::AuthenticationFailed)?;
        let nonce = self.nonce.next()?;
        self.key
            .open_in_place_separate_tag(nonce, Aad::from(&self.aad), tag, ciphertext, 0..)
            .map_err(|_| NoerError::AuthenticationFailed)?;
        buf.truncate(ct_len);
        Ok(Some(buf))
    }
}

pub struct EncryptWriter<W: Write> {
    inner: W,
    encryptor: ChunkEncryptor,
    buf: Vec<u8>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(inner: W, encryptor: ChunkEncryptor) -> Self {
        Self {
            inner,
            encryptor,
            buf: Vec::with_capacity(CHUNK_SIZE),
        }
    }

    pub fn finish(mut self) -> Result<W> {
        if !self.buf.is_empty() {
            let mut data = std::mem::take(&mut self.buf);
            self.encryptor
                .encrypt_chunk_owned(&mut data, &mut self.inner)?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut input = data;
        while !input.is_empty() {
            let space = CHUNK_SIZE - self.buf.len();
            let take = space.min(input.len());
            self.buf.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buf.len() == CHUNK_SIZE {
                let mut chunk = std::mem::take(&mut self.buf);
                self.encryptor
                    .encrypt_chunk_owned(&mut chunk, &mut self.inner)
                    .map_err(to_io_error)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let mut chunk = std::mem::take(&mut self.buf);
            self.encryptor
                .encrypt_chunk_owned(&mut chunk, &mut self.inner)
                .map_err(to_io_error)?;
        }
        self.inner.flush()
    }
}

pub struct DecryptReader<R: Read> {
    inner: R,
    decryptor: ChunkDecryptor,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(inner: R, decryptor: ChunkDecryptor) -> Self {
        Self {
            inner,
            decryptor,
            buf: Vec::new(),
            pos: 0,
            done: false,
        }
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            match self.decryptor.decrypt_chunk(&mut self.inner) {
                Ok(Some(chunk)) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Ok(None) => {
                    self.done = true;
                    return Ok(0);
                }
                Err(NoerError::AuthenticationFailed) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, AUTH_ERROR_TAG))
                }
                Err(err) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
                }
            }
        }
        let available = self.buf.len() - self.pos;
        let n = available.min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn to_io_error(err: NoerError) -> io::Error {
    io::Error::other(err.to_string())
}
