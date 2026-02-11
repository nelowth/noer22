use clap::Parser;
use noer22::utils;
use noer22::{cli, error, pack, unpack, wizard};

fn main() {
    utils::print_banner();
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> error::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Pack(args) => pack::pack(args),
        cli::Command::Unpack(args) => unpack::unpack(args),
        cli::Command::List(args) => unpack::list(args),
        cli::Command::Verify(args) => unpack::verify(args),
        cli::Command::Wizard => wizard::run(),
    }
}
