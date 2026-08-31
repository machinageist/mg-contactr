use std::io;

use clap::{Parser, Subcommand};
use mg_contacts::{
    AppError, config,
    keyring::{KeyLifecycle, KeyStatus},
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "mg-contacts", about = "Local-first contacts foundation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize the encrypted key after confirming a new passphrase
    Setup,
    /// Verify the passphrase for the encrypted key in this command only
    VerifyPassphrase,
    /// Report durable key and redacted database configuration state
    Status,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}: {}", error.code(), error);
        std::process::exit(error.exit_code().into());
    }
}

fn run() -> Result<(), AppError> {
    let cli = Cli::parse();
    let settings = config::load()?;
    let mut keys = KeyLifecycle::new(settings.paths.key_file);
    match cli.command {
        Command::Setup => {
            let passphrase = read_passphrase("New passphrase: ")?;
            let confirmation = read_passphrase("Confirm passphrase: ")?;
            keys.setup(&passphrase, &confirmation)?;
            println!("key_initialized; current_command=authenticated; next_process=locked");
        }
        Command::VerifyPassphrase => {
            let passphrase = read_passphrase("Passphrase: ")?;
            keys.verify_passphrase(&passphrase)?;
            println!("passphrase_verified; authentication_ends_with=this_command");
        }
        Command::Status => println!(
            "key={}; {}",
            status_name(keys.status()?),
            settings.database.redacted()
        ),
    }
    Ok(())
}

const fn status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::NotInitialized => "not_initialized",
        KeyStatus::Locked => "locked",
        KeyStatus::AuthenticatedThisProcess => "authenticated_this_process",
    }
}

fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>, io::Error> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}
