use crate::error::{NoerError, Result};
use age::{Decryptor, Encryptor, IdentityFile};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const FILE_KEY_LEN: usize = 32;

pub fn encrypt_file_key(key: &[u8; FILE_KEY_LEN], recipients: &[String]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(NoerError::InvalidFormat(
            "at least one age recipient is required".into(),
        ));
    }

    let parsed = recipients
        .iter()
        .map(|value| {
            value
                .parse::<age::x25519::Recipient>()
                .map_err(|_| NoerError::InvalidFormat(format!("invalid age recipient: {value}")))
        })
        .collect::<Result<Vec<_>>>()?;

    let encryptor = Encryptor::with_recipients(parsed.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| NoerError::InvalidFormat(format!("invalid age recipients: {e}")))?;

    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| NoerError::InvalidFormat(format!("age wrap failed: {e}")))?;
    writer
        .write_all(key)
        .map_err(|e| NoerError::InvalidFormat(format!("age write failed: {e}")))?;
    writer
        .finish()
        .map_err(|e| NoerError::InvalidFormat(format!("age finalize failed: {e}")))?;

    Ok(out)
}

pub fn decrypt_file_key(
    envelope: &[u8],
    identity_paths: &[PathBuf],
) -> Result<Zeroizing<[u8; FILE_KEY_LEN]>> {
    if identity_paths.is_empty() {
        return Err(NoerError::InvalidFormat(
            "archive uses age recipients; provide --age-identity <file>".into(),
        ));
    }

    let identities = load_identities(identity_paths)?;
    if identities.is_empty() {
        return Err(NoerError::InvalidFormat(
            "no identities found in age identity files".into(),
        ));
    }

    let decryptor = Decryptor::new_buffered(envelope)
        .map_err(|e| NoerError::InvalidFormat(format!("invalid age envelope: {e}")))?;
    if decryptor.is_scrypt() {
        return Err(NoerError::InvalidFormat(
            "unsupported age envelope mode".into(),
        ));
    }
    let mut reader = decryptor
        .decrypt(
            identities
                .iter()
                .map(|id| id.as_ref() as &dyn age::Identity),
        )
        .map_err(|_| NoerError::AuthenticationFailed)?;

    let mut key_bytes = Vec::new();
    reader
        .read_to_end(&mut key_bytes)
        .map_err(|e| NoerError::InvalidFormat(format!("failed to read age envelope: {e}")))?;

    if key_bytes.len() != FILE_KEY_LEN {
        return Err(NoerError::InvalidFormat(
            "invalid wrapped key length".into(),
        ));
    }

    let mut key = Zeroizing::new([0u8; FILE_KEY_LEN]);
    key.as_mut().copy_from_slice(&key_bytes);
    Ok(key)
}

fn load_identities(paths: &[PathBuf]) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut identities = Vec::new();
    for path in paths {
        let file = IdentityFile::from_file(path_to_string(path)).map_err(|e| {
            NoerError::InvalidFormat(format!(
                "failed to read age identity file {}: {e}",
                path.display()
            ))
        })?;
        let mut parsed = file.into_identities().map_err(|e| {
            NoerError::InvalidFormat(format!(
                "failed to parse age identity file {}: {e}",
                path.display()
            ))
        })?;
        identities.append(&mut parsed);
    }
    Ok(identities)
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}
