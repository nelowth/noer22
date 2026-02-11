use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

fn default_level() -> i32 {
    8
}

#[derive(Parser)]
#[command(
    name = "noer22",
    version,
    about = "Pack and encrypt files into .noer archives"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Pack and encrypt files/folders
    Pack(PackArgs),
    /// Extract and decrypt a .noer archive
    Unpack(UnpackArgs),
    /// List archive contents
    List(ListArgs),
    /// Verify archive integrity and password
    Verify(VerifyArgs),
    /// Interactive wizard (TUI)
    Wizard,
}

#[derive(Args, Clone)]
pub struct PackArgs {
    /// Input files or folders
    #[arg(value_name = "INPUT", required = true)]
    pub inputs: Vec<PathBuf>,
    /// Output .noer archive
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,
    /// Encryption password
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: Option<String>,
    /// Optional keyfile used as additional key material
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    /// Encrypt archive file-key to one or more age recipients (AGE1...)
    #[arg(long = "age-recipient", value_name = "RECIPIENT")]
    pub age_recipients: Vec<String>,
    /// Compression level (-22 to 22)
    #[arg(short = 'l', long, default_value_t = default_level())]
    pub level: i32,
    /// Encryption algorithm
    #[arg(long, value_enum, default_value_t = CipherChoice::ChaCha20Poly1305)]
    pub cipher: CipherChoice,
    /// Argon2id memory in MiB
    #[arg(long, default_value_t = 64)]
    pub kdf_mem: u32,
    /// Argon2id iterations
    #[arg(long, default_value_t = 3)]
    pub kdf_iters: u32,
    /// Argon2id parallelism
    #[arg(long, default_value_t = 4)]
    pub kdf_parallelism: u32,
    /// Threads for Zstd compression
    #[arg(long)]
    pub threads: Option<usize>,
    /// Experimental: parallel chunk encryption while preserving deterministic output order
    #[arg(long, default_value_t = false)]
    pub parallel_crypto: bool,
    /// Path to incremental index file (.json). Only changed/new files are packed.
    #[arg(long, value_name = "FILE")]
    pub incremental_index: Option<PathBuf>,
    /// Generate external checksum sidecar for the archive
    #[arg(long, value_enum)]
    pub checksum: Option<ChecksumChoice>,
    /// Output path for the checksum sidecar
    #[arg(long, value_name = "FILE", requires = "checksum")]
    pub checksum_output: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct UnpackArgs {
    /// .noer archive
    #[arg(value_name = "FILE")]
    pub archive: PathBuf,
    /// Decryption password
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: Option<String>,
    /// Optional keyfile used as additional key material
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    /// Age identity file path (can be repeated)
    #[arg(long = "age-identity", value_name = "FILE")]
    pub age_identities: Vec<PathBuf>,
    /// Output directory
    #[arg(short = 'C', long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Verify archive file against an external checksum sidecar before extracting
    #[arg(long, value_name = "FILE")]
    pub checksum_file: Option<PathBuf>,
    /// Algorithm used when sidecar does not include an algorithm prefix
    #[arg(long, value_enum, requires = "checksum_file")]
    pub checksum_algo: Option<ChecksumChoice>,
}

#[derive(Args, Clone)]
pub struct ListArgs {
    /// .noer archive
    #[arg(value_name = "FILE")]
    pub archive: PathBuf,
    /// Password for metadata decryption
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: Option<String>,
    /// Optional keyfile used as additional key material
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    /// Age identity file path (can be repeated)
    #[arg(long = "age-identity", value_name = "FILE")]
    pub age_identities: Vec<PathBuf>,
    /// Show extended per-entry details
    #[arg(short, long)]
    pub long: bool,
}

#[derive(Args, Clone)]
pub struct VerifyArgs {
    /// .noer archive
    #[arg(value_name = "FILE")]
    pub archive: PathBuf,
    /// Password used to verify/decrypt archive payload
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: Option<String>,
    /// Optional keyfile used as additional key material
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    /// Age identity file path (can be repeated)
    #[arg(long = "age-identity", value_name = "FILE")]
    pub age_identities: Vec<PathBuf>,
    /// Verify archive file against an external checksum sidecar
    #[arg(long, value_name = "FILE")]
    pub checksum_file: Option<PathBuf>,
    /// Algorithm used when sidecar does not include an algorithm prefix
    #[arg(long, value_enum, requires = "checksum_file")]
    pub checksum_algo: Option<ChecksumChoice>,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum CipherChoice {
    #[value(name = "chacha")]
    ChaCha20Poly1305,
    #[value(name = "aes")]
    Aes256Gcm,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ChecksumChoice {
    #[value(name = "sha256")]
    Sha256,
    #[value(name = "blake3")]
    Blake3,
}
