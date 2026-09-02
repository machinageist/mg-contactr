#![allow(clippy::missing_errors_doc)]

pub mod audit;
pub mod config;
pub mod envelope;
pub mod keyring;
pub mod privacy;
mod secure_fs;
pub mod tombstone;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Key(#[from] keyring::KeyError),
    #[error("could not read passphrase")]
    Io(#[from] std::io::Error),
}

impl AppError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_invalid",
            Self::Key(_) => "key_lifecycle_failed",
            Self::Io(_) => "passphrase_input_failed",
        }
    }

    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) => 78,
            Self::Key(_) => 65,
            Self::Io(_) => 74,
        }
    }
}
