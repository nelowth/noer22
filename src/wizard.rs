use crate::cli::{CipherChoice, ListArgs, PackArgs, UnpackArgs, VerifyArgs};
use crate::error::Result;
use crate::{pack, unpack};
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use std::path::PathBuf;

pub fn run() -> Result<()> {
    let theme = ColorfulTheme::default();

    let mode = Select::with_theme(&theme)
        .with_prompt("Choose mode")
        .items(&[
            "Pack archive",
            "Extract archive",
            "List archive contents",
            "Verify archive integrity",
        ])
        .default(0)
        .interact()
        .unwrap();

    match mode {
        0 => pack_flow(&theme),
        1 => unpack_flow(&theme),
        2 => list_flow(&theme),
        _ => verify_flow(&theme),
    }
}

fn pack_flow(theme: &ColorfulTheme) -> Result<()> {
    let inputs_str: String = Input::with_theme(theme)
        .with_prompt("Input files/folders (comma-separated)")
        .interact_text()
        .unwrap();
    let inputs: Vec<PathBuf> = inputs_str
        .split(',')
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();

    let output_str: String = Input::with_theme(theme)
        .with_prompt("Output .noer archive")
        .default("archive.noer".into())
        .interact_text()
        .unwrap();
    let output = PathBuf::from(output_str);

    let password = Password::with_theme(theme)
        .with_prompt("Password")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .unwrap();

    let cipher_idx = Select::with_theme(theme)
        .with_prompt("Cipher")
        .items(&["ChaCha20-Poly1305", "AES-256-GCM"])
        .default(0)
        .interact()
        .unwrap();
    let cipher = match cipher_idx {
        0 => CipherChoice::ChaCha20Poly1305,
        _ => CipherChoice::Aes256Gcm,
    };

    let level: i32 = Input::with_theme(theme)
        .with_prompt("Compression level (-22..22)")
        .default(3)
        .interact_text()
        .unwrap();

    let threads: usize = Input::with_theme(theme)
        .with_prompt("Compression threads (0 = auto)")
        .default(0)
        .interact_text()
        .unwrap();

    let kdf_mem: u32 = Input::with_theme(theme)
        .with_prompt("Argon2 memory (MiB)")
        .default(64)
        .interact_text()
        .unwrap();
    let kdf_iters: u32 = Input::with_theme(theme)
        .with_prompt("Argon2 iterations")
        .default(3)
        .interact_text()
        .unwrap();
    let kdf_parallelism: u32 = Input::with_theme(theme)
        .with_prompt("Argon2 parallelism")
        .default(4)
        .interact_text()
        .unwrap();

    println!("Packing archive...");
    pack::pack(PackArgs {
        inputs,
        output,
        password,
        level,
        cipher,
        kdf_mem,
        kdf_iters,
        kdf_parallelism,
        threads: if threads == 0 { None } else { Some(threads) },
    })
}

fn unpack_flow(theme: &ColorfulTheme) -> Result<()> {
    let archive_str: String = Input::with_theme(theme)
        .with_prompt(".noer archive")
        .interact_text()
        .unwrap();
    let archive = PathBuf::from(archive_str);
    let output_str: String = Input::with_theme(theme)
        .with_prompt("Output directory")
        .default("out".into())
        .interact_text()
        .unwrap();
    let output = PathBuf::from(output_str);
    let password = Password::with_theme(theme)
        .with_prompt("Password")
        .interact()
        .unwrap();

    println!("Extracting archive...");
    unpack::unpack(UnpackArgs {
        archive,
        password,
        output: Some(output),
    })
}

fn list_flow(theme: &ColorfulTheme) -> Result<()> {
    let archive_str: String = Input::with_theme(theme)
        .with_prompt(".noer archive")
        .interact_text()
        .unwrap();
    let archive = PathBuf::from(archive_str);
    let password = Password::with_theme(theme)
        .with_prompt("Password")
        .interact()
        .unwrap();
    let long: bool = Select::with_theme(theme)
        .with_prompt("Listing format")
        .items(&["Simple", "Detailed"])
        .default(0)
        .interact()
        .unwrap()
        == 1;

    unpack::list(ListArgs {
        archive,
        password,
        long,
    })
}

fn verify_flow(theme: &ColorfulTheme) -> Result<()> {
    let archive_str: String = Input::with_theme(theme)
        .with_prompt(".noer archive")
        .interact_text()
        .unwrap();
    let archive = PathBuf::from(archive_str);
    let password = Password::with_theme(theme)
        .with_prompt("Password")
        .interact()
        .unwrap();

    unpack::verify(VerifyArgs { archive, password })
}
