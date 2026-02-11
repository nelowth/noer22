use crate::error::{NoerError, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

pub fn print_banner() {
    const GOLD: &str = "\x1b[38;5;179m";
    const CRIMSON: &str = "\x1b[38;5;131m";
    const DIM: &str = "\x1b[38;5;245m";
    const RESET: &str = "\x1b[0m";
    println!(
        "{DIM}------------------------------------------------{RESET}\n\
{GOLD}  _ __   ___   ___ _ __ ___  ___ ___ {RESET}\n\
{GOLD} | '_ \\ / _ \\ / _ \\ '__/ _ \\/ __/ __|{RESET}\n\
{GOLD} | | | | (_) |  __/ | |  __/\\__ \\__ \\{RESET}\n\
{GOLD} |_| |_|\\___/ \\___|_|  \\___||___/___/{RESET}\n\
{CRIMSON} noer22 :: compression + aead secrecy{RESET}"
    );
}

pub fn progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    let style =
        ProgressStyle::with_template("{msg} [{bar:40.yellow/black}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("=>-");
    pb.set_style(style);
    pb.set_message(message.to_string());
    pb
}

pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub struct ProgressReader<R: Read> {
    inner: R,
    pb: ProgressBar,
}

impl<R: Read> ProgressReader<R> {
    pub fn new(inner: R, pb: ProgressBar) -> Self {
        Self { inner, pb }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.pb.inc(n as u64);
        }
        Ok(n)
    }
}

pub struct ConcatReader {
    paths: Vec<PathBuf>,
    index: usize,
    current: Option<BufReader<File>>,
}

impl ConcatReader {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            index: 0,
            current: None,
        }
    }

    fn open_next(&mut self) -> io::Result<()> {
        if self.index >= self.paths.len() {
            self.current = None;
            return Ok(());
        }
        let file = File::open(&self.paths[self.index])?;
        self.current = Some(BufReader::with_capacity(256 * 1024, file));
        self.index += 1;
        Ok(())
    }
}

impl Read for ConcatReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.is_none() {
                self.open_next()?;
                if self.current.is_none() {
                    return Ok(0);
                }
            }
            let done = match self.current.as_mut() {
                Some(reader) => reader.read(buf)?,
                None => 0,
            };
            if done == 0 {
                self.current = None;
                continue;
            }
            return Ok(done);
        }
    }
}

pub fn sanitize_rel_path(path: &str) -> Result<PathBuf> {
    if path.trim().is_empty() {
        return Err(NoerError::InvalidFormat("empty path in archive".into()));
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(NoerError::InvalidFormat("absolute path in archive".into()));
    }

    let mut normalized = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(NoerError::InvalidFormat(
                    "path contains '..' or invalid prefix".into(),
                ));
            }
            Component::CurDir => {}
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(NoerError::InvalidFormat("empty path in archive".into()));
    }
    Ok(normalized)
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut idx = 0;
    while v >= 1024.0 && idx < UNITS.len() - 1 {
        v /= 1024.0;
        idx += 1;
    }
    format!("{:.2} {}", v, UNITS[idx])
}

pub fn copy_exact<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    pb: &ProgressBar,
) -> io::Result<()> {
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "insufficient data",
            ));
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
        pb.inc(n as u64);
    }
    Ok(())
}

#[derive(Default)]
pub struct RelPathSet {
    files: HashSet<String>,
    dirs: HashSet<String>,
}

impl RelPathSet {
    pub fn insert(&mut self, path: &str, is_dir: bool) -> Result<()> {
        let normalized = normalize_rel(path)?;
        if is_dir {
            self.insert_dir(&normalized)
        } else {
            self.insert_file(&normalized)
        }
    }

    fn insert_dir(&mut self, path: &str) -> Result<()> {
        if self.files.contains(path) {
            return Err(NoerError::InvalidFormat(format!(
                "path conflict (file vs directory): {path}"
            )));
        }
        if has_file_ancestor(path, &self.files) {
            return Err(NoerError::InvalidFormat(format!(
                "path conflict (file parent): {path}"
            )));
        }
        self.dirs.insert(path.to_string());
        Ok(())
    }

    fn insert_file(&mut self, path: &str) -> Result<()> {
        if self.files.contains(path) || self.dirs.contains(path) {
            return Err(NoerError::InvalidFormat(format!("duplicate path: {path}")));
        }
        if has_file_ancestor(path, &self.files) {
            return Err(NoerError::InvalidFormat(format!(
                "path conflict (file parent): {path}"
            )));
        }
        if has_dir_descendant(path, &self.dirs) {
            return Err(NoerError::InvalidFormat(format!(
                "path conflict (directory child): {path}"
            )));
        }
        self.files.insert(path.to_string());
        Ok(())
    }
}

fn normalize_rel(path: &str) -> Result<String> {
    let normalized = sanitize_rel_path(path)?;
    Ok(normalized.to_string_lossy().replace('\\', "/"))
}

fn has_file_ancestor(path: &str, files: &HashSet<String>) -> bool {
    let mut rest = path;
    while let Some((parent, _)) = rest.rsplit_once('/') {
        if files.contains(parent) {
            return true;
        }
        rest = parent;
    }
    false
}

fn has_dir_descendant(path: &str, dirs: &HashSet<String>) -> bool {
    let prefix = format!("{path}/");
    dirs.iter().any(|entry| entry.starts_with(&prefix))
}
