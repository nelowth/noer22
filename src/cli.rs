use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
    pub password: String,
    /// Compression level (-22 to 22)
    #[arg(short = 'l', long, default_value_t = 6)]
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
}

#[derive(Args, Clone)]
pub struct UnpackArgs {
    /// .noer archive
    #[arg(value_name = "FILE")]
    pub archive: PathBuf,
    /// Decryption password
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: String,
    /// Output directory
    #[arg(short = 'C', long, value_name = "DIR")]
    pub output: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct ListArgs {
    /// .noer archive
    #[arg(value_name = "FILE")]
    pub archive: PathBuf,
    /// Password for metadata decryption
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: String,
    /// Show extended per-entry details
    #[arg(short, long)]
    pub long: bool,
}

#[derive(Args, Clone)]
pub struct VerifyArgs {
    /// .noer archive
    #[arg(value_name = "FILE")]
    pub archive: PathBuf,
    /// Password used to verify integrity
    #[arg(short, long, value_name = "PASSWORD")]
    pub password: String,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum CipherChoice {
    #[value(name = "chacha")]
    ChaCha20Poly1305,
    #[value(name = "aes")]
    Aes256Gcm,
}
