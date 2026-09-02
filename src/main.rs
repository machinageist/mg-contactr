use std::io::{self, BufRead};

use clap::{Parser, Subcommand};
use mg_contacts::{
    AppError, config, contact,
    keyring::{KeyLifecycle, KeyStatus},
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "mg-contacts", about = "Local-first encrypted contacts")]
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
    /// Create a contact; fields are read from stdin after authentication
    Create { id: String },
    /// Read a contact
    Read { id: String },
    /// List active contacts
    List,
    /// Update a contact; fields are read from stdin after authentication
    Update { id: String },
    /// Soft-delete a contact
    Delete { id: String },
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
        command => {
            let passphrase = read_passphrase("Passphrase: ")?;
            keys.verify_passphrase(&passphrase)?;
            let path = settings.paths.data_dir.join("contacts.log");
            match command {
                Command::Create { id } => {
                    let item = contact::create(
                        &keys,
                        &path,
                        &id,
                        &read_value("Name: ")?,
                        &read_value("Email: ")?,
                        &read_value("Phone: ")?,
                    )?;
                    print_view(&item);
                }
                Command::Read { id } => print_view(&contact::get(&keys, &path, &id)?),
                Command::List => {
                    for item in contact::list(&keys, &path)? {
                        print_view(&item);
                    }
                }
                Command::Update { id } => {
                    let item = contact::update(
                        &keys,
                        &path,
                        &id,
                        &read_value("Name: ")?,
                        &read_value("Email: ")?,
                        &read_value("Phone: ")?,
                    )?;
                    print_view(&item);
                }
                Command::Delete { id } => print_view(&contact::soft_delete(&keys, &path, &id)?),
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}

fn print_view(item: &contact::ContactView) {
    println!(
        "{}\t{}\t{}\t{}\trevision={}",
        item.id, item.name, item.email, item.phone, item.revision
    );
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

fn read_value(prompt: &str) -> Result<String, io::Error> {
    eprint!("{prompt}");
    let mut value = String::new();
    io::stdin().lock().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}
