use std::{collections::HashMap, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const APP: &str = "mg-contacts";
const DEFAULT_SOCKET: &str = "/run/postgresql";
const DEFAULT_DATABASE: &str = "mg_contacts";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("HOME is unset and an XDG base directory is missing")]
    MissingHome,
    #[error("XDG base directories must be absolute paths")]
    RelativeXdgPath,
    #[error("configuration directory is not private")]
    InsecureDirectory,
    #[error("secure local storage is unsupported on this platform")]
    UnsupportedStorage,
    #[error("configuration file is not private")]
    InsecureFile,
    #[error("configuration file could not be read")]
    Read,
    #[error("configuration file exceeds the 64 KiB limit")]
    TooLarge,
    #[error("configuration file is invalid")]
    Parse,
    #[error("database URL is invalid")]
    InvalidDatabaseUrl,
    #[error(
        "database configuration is local-only and must use localhost, loopback, or a Unix socket"
    )]
    RemoteDatabase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub key_file: PathBuf,
}

impl ConfigPaths {
    pub fn from_env<S: std::hash::BuildHasher>(
        vars: &HashMap<String, String, S>,
    ) -> Result<Self, ConfigError> {
        let home = vars.get("HOME").map(PathBuf::from);
        let base = |key: &str, fallback: &str| {
            let path = vars.get(key).map_or_else(
                || {
                    home.as_ref()
                        .map(|p| p.join(fallback))
                        .ok_or(ConfigError::MissingHome)
                },
                |value| Ok(PathBuf::from(value)),
            )?;
            if !path.is_absolute() {
                return Err(ConfigError::RelativeXdgPath);
            }
            Ok(path)
        };
        let config_dir = base("XDG_CONFIG_HOME", ".config")?.join(APP);
        let data_dir = base("XDG_DATA_HOME", ".local/share")?.join(APP);
        Ok(Self {
            config_file: config_dir.join("config.toml"),
            config_dir,
            key_file: data_dir.join("keyring.json"),
            data_dir,
            state_dir: base("XDG_STATE_HOME", ".local/state")?.join(APP),
            cache_dir: base("XDG_CACHE_HOME", ".cache")?.join(APP),
        })
    }

    pub fn ensure_private_dirs(&self) -> Result<(), ConfigError> {
        for path in [
            &self.config_dir,
            &self.data_dir,
            &self.state_dir,
            &self.cache_dir,
        ] {
            crate::secure_fs::ensure_private_dir(path).map_err(classify_directory_error)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Environment,
    File,
    Default,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseUrl(String);
impl DatabaseUrl {
    pub fn parse(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        validate_local_database_url(&value)?;
        Ok(Self(value))
    }
}
impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabaseUrl(\"[REDACTED]\")")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub url: DatabaseUrl,
    pub source: ConfigSource,
}
impl DatabaseConfig {
    #[must_use]
    pub fn redacted(&self) -> String {
        format!(
            "PostgreSQL ({:?}; credentials, parameters, and paths redacted)",
            self.source
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub paths: ConfigPaths,
    pub database: DatabaseConfig,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    database: FileDatabase,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDatabase {
    url: Option<String>,
}

pub fn resolve_config<S: std::hash::BuildHasher>(
    vars: &HashMap<String, String, S>,
    file_contents: Option<&str>,
) -> Result<AppConfig, ConfigError> {
    let paths = ConfigPaths::from_env(vars)?;
    let file: FileConfig = file_contents.map_or_else(
        || Ok(FileConfig::default()),
        |v| toml::from_str(v).map_err(|_| ConfigError::Parse),
    )?;
    let (raw, source) = if let Some(v) = vars.get("MG_CONTACTS_DATABASE_URL") {
        (v.clone(), ConfigSource::Environment)
    } else if let Some(v) = file.database.url {
        (v, ConfigSource::File)
    } else {
        (
            format!("postgresql:///{DEFAULT_DATABASE}?host={DEFAULT_SOCKET}"),
            ConfigSource::Default,
        )
    };
    Ok(AppConfig {
        paths,
        database: DatabaseConfig {
            url: DatabaseUrl::parse(raw)?,
            source,
        },
    })
}

pub fn load() -> Result<AppConfig, ConfigError> {
    let vars = std::env::vars().collect::<HashMap<_, _>>();
    let paths = ConfigPaths::from_env(&vars)?;
    paths.ensure_private_dirs()?;
    let file = crate::secure_fs::read_optional_private_file(
        &paths.config_file,
        crate::secure_fs::MAX_CONFIG_FILE_BYTES,
    )
    .map_err(classify_config_read_error)?
    .map(|bytes| String::from_utf8(bytes).map_err(|_| ConfigError::Parse))
    .transpose()?;
    resolve_config(&vars, file.as_deref())
}

#[allow(clippy::needless_pass_by_value)] // `Result::map_err` supplies ownership
fn classify_directory_error(error: crate::secure_fs::SecureFsError) -> ConfigError {
    use crate::secure_fs::SecureFsError;
    match error {
        SecureFsError::Unsupported => ConfigError::UnsupportedStorage,
        SecureFsError::InsecureDirectory => ConfigError::InsecureDirectory,
        SecureFsError::InsecureFile
        | SecureFsError::NotFound
        | SecureFsError::AlreadyExists
        | SecureFsError::TooLarge
        | SecureFsError::InvalidPath
        | SecureFsError::Io(_) => ConfigError::Read,
    }
}

#[allow(clippy::needless_pass_by_value)] // `Result::map_err` supplies ownership
fn classify_config_read_error(error: crate::secure_fs::SecureFsError) -> ConfigError {
    use crate::secure_fs::SecureFsError;
    match error {
        SecureFsError::Unsupported => ConfigError::UnsupportedStorage,
        SecureFsError::InsecureFile | SecureFsError::InsecureDirectory => ConfigError::InsecureFile,
        SecureFsError::TooLarge => ConfigError::TooLarge,
        SecureFsError::NotFound
        | SecureFsError::AlreadyExists
        | SecureFsError::InvalidPath
        | SecureFsError::Io(_) => ConfigError::Read,
    }
}

pub fn validate_local_database_url(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidDatabaseUrl)?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(ConfigError::RemoteDatabase);
    }
    if let Some(host) = url.host_str() {
        validate_host_list(host, false)?;
    }
    let mut saw_host = false;
    for (key, value) in url.query_pairs() {
        if key == "host" || key == "hostaddr" {
            saw_host = true;
            validate_host_list(&value, key == "hostaddr")?;
        }
    }
    if url.host_str().is_none() && !saw_host {
        return Err(ConfigError::RemoteDatabase);
    }
    Ok(())
}

fn validate_host_list(value: &str, address_only: bool) -> Result<(), ConfigError> {
    let hosts: Vec<_> = value.split(',').map(str::trim).collect();
    if hosts.is_empty() || hosts.iter().any(|host| host.is_empty()) {
        return Err(ConfigError::RemoteDatabase);
    }
    for host in hosts {
        if !address_only && host.starts_with('/') && !host.contains('\0') {
            continue;
        }
        let normalized = host.trim_matches(['[', ']']);
        if normalized.eq_ignore_ascii_case("localhost")
            || normalized
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            continue;
        }
        return Err(ConfigError::RemoteDatabase);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn precedence_is_env_then_file() {
        let mut v = HashMap::from([
            (String::from("HOME"), String::from("/tmp/h")),
            (
                String::from("MG_CONTACTS_DATABASE_URL"),
                String::from("postgres://localhost/env"),
            ),
        ]);
        let file = "[database]\nurl='postgres://localhost/file'";
        assert_eq!(
            resolve_config(&v, Some(file)).unwrap().database.source,
            ConfigSource::Environment
        );
        v.remove("MG_CONTACTS_DATABASE_URL");
        assert_eq!(
            resolve_config(&v, Some(file)).unwrap().database.source,
            ConfigSource::File
        );
    }
    #[test]
    fn local_url_validation_covers_all_libpq_hosts() {
        for u in [
            "postgres://localhost/db",
            "postgres://127.0.0.1/db",
            "postgres://[::1]/db",
            "postgresql:///db?host=%2Fvar%2Frun%2Fpostgresql",
            "postgresql:///db?host=localhost,127.0.0.1&hostaddr=127.0.0.1",
            "postgresql:///db?host=%2Ftmp%2Fpg,localhost",
            "postgresql:///db?host=localhost&host=127.0.0.1",
        ] {
            assert!(validate_local_database_url(u).is_ok(), "{u}");
        }
        for u in [
            "postgres://example.test/db",
            "postgres://localhost.evil/db",
            "http://localhost/db",
            "postgresql:///db?host=localhost,example.test",
            "postgresql:///db?hostaddr=127.0.0.1,8.8.8.8",
            "postgresql:///db?host=%2Ftmp%2Fpg&hostaddr=192.168.1.2",
            "postgresql:///db?host=",
        ] {
            assert!(validate_local_database_url(u).is_err(), "{u}");
        }
    }
    #[test]
    fn xdg_overrides_must_be_absolute() {
        let v = HashMap::from([
            (String::from("HOME"), String::from("/tmp/h")),
            (String::from("XDG_CONFIG_HOME"), String::from("relative")),
        ]);
        assert!(matches!(
            ConfigPaths::from_env(&v),
            Err(ConfigError::RelativeXdgPath)
        ));
    }
    #[test]
    fn redaction_never_exposes_credentials_or_private_query_values() {
        let c = DatabaseUrl::parse(
            "postgresql:///db?host=%2Frun%2Fpostgresql&password=secret&passfile=%2Fhome%2Fprivate%2F.pgpass&sslkey=%2Fhome%2Fprivate%2Fclient.key",
        )
        .unwrap();
        let d = DatabaseConfig {
            url: c,
            source: ConfigSource::File,
        };
        let output = d.redacted();
        for sensitive in ["secret", "/home/private", "password", "passfile", "sslkey"] {
            assert!(
                !output.contains(sensitive),
                "redacted status leaked {sensitive}"
            );
        }
        assert!(output.contains("File"));
        assert!(output.contains("redacted"));
        assert!(!format!("{d:?}").contains("secret"));
    }

    #[test]
    fn unknown_configuration_is_rejected_without_echoing_values() {
        let vars = HashMap::from([(String::from("HOME"), String::from("/tmp/h"))]);
        for invalid in [
            "[databse]\nurl='postgres://localhost/db'",
            "[database]\nurll='postgres://localhost/db'",
            "[database]\nurl='postgres://localhost/db'\nunexpected='secret-value'",
        ] {
            let error = resolve_config(&vars, Some(invalid)).unwrap_err();
            assert!(matches!(error, ConfigError::Parse));
            assert_eq!(error.to_string(), "configuration file is invalid");
            assert!(!error.to_string().contains("secret-value"));
        }
    }

    #[test]
    fn secure_read_failures_have_stable_redacted_classes() {
        assert!(matches!(
            classify_config_read_error(crate::secure_fs::SecureFsError::TooLarge),
            ConfigError::TooLarge
        ));
        assert!(matches!(
            classify_config_read_error(crate::secure_fs::SecureFsError::InsecureFile),
            ConfigError::InsecureFile
        ));
        assert!(matches!(
            classify_config_read_error(crate::secure_fs::SecureFsError::Unsupported),
            ConfigError::UnsupportedStorage
        ));
        assert!(matches!(
            classify_config_read_error(crate::secure_fs::SecureFsError::Io(std::io::Error::other(
                "/private/path and secret"
            ))),
            ConfigError::Read
        ));
    }
}
