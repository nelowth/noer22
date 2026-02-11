use std::io;

#[derive(thiserror::Error, Debug)]
pub enum NoerError {
    #[error("wrong password or corrupted archive")]
    AuthenticationFailed,
    #[error("invalid archive: {0}")]
    InvalidFormat(String),
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
    #[error("argon2 error: {0}")]
    Argon2(String),
}

pub type Result<T> = std::result::Result<T, NoerError>;

impl From<argon2::Error> for NoerError {
    fn from(err: argon2::Error) -> Self {
        NoerError::Argon2(err.to_string())
    }
}
