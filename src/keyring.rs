use std::path::PathBuf;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MIN_PASSPHRASE_CHARS: usize = 12;
const MAX_PASSPHRASE_BYTES: usize = 1024;
const AAD: &[u8] = b"mg-contacts user-held key v1";
const KDF_ALGORITHM: &str = "argon2id";
const KDF_VERSION: u32 = 0x13;
const KDF_MEMORY_KIB: u32 = 19_456;
const KDF_TIME_COST: u32 = 2;
const KDF_PARALLELISM: u32 = 1;
const KDF_OUTPUT_BYTES: u32 = 32;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key file already exists")]
    AlreadyInitialized,
    #[error("key file is unavailable")]
    Io(#[source] std::io::Error),
    #[error("key file is invalid")]
    InvalidFile,
    #[error("passphrase is invalid or could not authenticate the key")]
    InvalidPassphrase,
    #[error("passphrase must contain at least 12 characters")]
    WeakPassphrase,
    #[error("passphrase confirmation did not match")]
    PassphraseMismatch,
    #[error("key encryption failed")]
    Encryption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    NotInitialized,
    Locked,
    AuthenticatedThisProcess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfContract {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_bytes: u32,
}

impl KdfContract {
    fn supported() -> Self {
        Self {
            algorithm: KDF_ALGORITHM.to_owned(),
            version: KDF_VERSION,
            memory_kib: KDF_MEMORY_KIB,
            time_cost: KDF_TIME_COST,
            parallelism: KDF_PARALLELISM,
            output_bytes: KDF_OUTPUT_BYTES,
        }
    }

    fn params(&self) -> Result<Params, KeyError> {
        if self != &Self::supported() {
            return Err(KeyError::InvalidFile);
        }
        Params::new(
            self.memory_kib,
            self.time_cost,
            self.parallelism,
            Some(self.output_bytes as usize),
        )
        .map_err(|_| KeyError::InvalidFile)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    version: u8,
    kdf: KdfContract,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub struct KeyLifecycle {
    path: PathBuf,
    key: Option<Zeroizing<[u8; KEY_BYTES]>>,
}

impl KeyLifecycle {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            key: None,
        }
    }

    pub fn status(&self) -> Result<KeyStatus, KeyError> {
        if self.key.is_some() {
            return Ok(KeyStatus::AuthenticatedThisProcess);
        }
        if crate::secure_fs::regular_file_exists(&self.path)
            .map_err(|error| KeyError::Io(error.into_io()))?
        {
            Ok(KeyStatus::Locked)
        } else {
            Ok(KeyStatus::NotInitialized)
        }
    }

    pub fn setup(&mut self, passphrase: &str, confirmation: &str) -> Result<(), KeyError> {
        match crate::secure_fs::regular_file_exists(&self.path) {
            Ok(true) => return Err(KeyError::AlreadyInitialized),
            Ok(false) | Err(crate::secure_fs::SecureFsError::NotFound) => {}
            Err(error) => return Err(KeyError::Io(error.into_io())),
        }
        validate_new_passphrase(passphrase, confirmation)?;

        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        rand::fill(&mut *key);
        let mut salt = [0_u8; SALT_BYTES];
        rand::fill(&mut salt);
        let mut nonce = [0_u8; NONCE_BYTES];
        rand::fill(&mut nonce);
        let stored = encrypt_key(&key, passphrase, &salt, &nonce)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec_pretty(&stored).map_err(|_| KeyError::Encryption)?);
        crate::secure_fs::install_new_file(&self.path, &bytes).map_err(|error| match error {
            crate::secure_fs::SecureFsError::AlreadyExists => KeyError::AlreadyInitialized,
            other => KeyError::Io(other.into_io()),
        })?;
        self.key = Some(key);
        Ok(())
    }

    pub fn verify_passphrase(&mut self, passphrase: &str) -> Result<(), KeyError> {
        if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES {
            return Err(KeyError::InvalidPassphrase);
        }
        let raw = Zeroizing::new(
            crate::secure_fs::read_private_file(&self.path, crate::secure_fs::MAX_KEY_FILE_BYTES)
                .map_err(|error| KeyError::Io(error.into_io()))?,
        );
        let stored: StoredKey = serde_json::from_slice(&raw).map_err(|_| KeyError::InvalidFile)?;
        if stored.version != 1 {
            return Err(KeyError::InvalidFile);
        }
        let params = stored.kdf.params()?;
        let salt = Zeroizing::new(B64.decode(stored.salt).map_err(|_| KeyError::InvalidFile)?);
        if salt.len() != SALT_BYTES {
            return Err(KeyError::InvalidFile);
        }
        let derived =
            derive_key(passphrase, &salt, params).map_err(|_| KeyError::InvalidPassphrase)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&*derived).map_err(|_| KeyError::InvalidFile)?;
        let nonce = B64
            .decode(stored.nonce)
            .map_err(|_| KeyError::InvalidFile)?;
        let mut plaintext = Zeroizing::new(
            B64.decode(stored.ciphertext)
                .map_err(|_| KeyError::InvalidFile)?,
        );
        if nonce.len() != NONCE_BYTES || plaintext.len() != KEY_BYTES + TAG_BYTES {
            return Err(KeyError::InvalidFile);
        }
        let tag_start = plaintext.len() - TAG_BYTES;
        let tag_bytes: [u8; TAG_BYTES] = plaintext[tag_start..]
            .try_into()
            .map_err(|_| KeyError::InvalidFile)?;
        plaintext.truncate(tag_start);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                AAD,
                &mut plaintext,
                chacha20poly1305::Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| KeyError::InvalidPassphrase)?;

        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        key.copy_from_slice(&plaintext);
        self.key = Some(key);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.key.take();
    }

    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.key.is_some()
    }
}

fn validate_new_passphrase(passphrase: &str, confirmation: &str) -> Result<(), KeyError> {
    if passphrase.len() > MAX_PASSPHRASE_BYTES || confirmation.len() > MAX_PASSPHRASE_BYTES {
        return Err(KeyError::InvalidPassphrase);
    }
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(KeyError::WeakPassphrase);
    }
    if !bool::from(passphrase.as_bytes().ct_eq(confirmation.as_bytes())) {
        return Err(KeyError::PassphraseMismatch);
    }
    Ok(())
}

fn encrypt_key(
    key: &[u8; KEY_BYTES],
    passphrase: &str,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<StoredKey, KeyError> {
    let kdf = KdfContract::supported();
    let params = kdf.params()?;
    let derived = derive_key(passphrase, salt, params).map_err(|_| KeyError::Encryption)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&*derived).map_err(|_| KeyError::Encryption)?;
    let mut ciphertext = Zeroizing::new(key.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), AAD, &mut ciphertext)
        .map_err(|_| KeyError::Encryption)?;
    ciphertext.extend_from_slice(&tag);
    Ok(StoredKey {
        version: 1,
        kdf,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(&*ciphertext),
    })
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    params: Params,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, argon2::Error> {
    let mut derived = Zeroizing::new([0_u8; KEY_BYTES]);
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into_with_memory(
        passphrase.as_bytes(),
        salt,
        &mut *derived,
        &mut *memory,
    )?;
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const PASSPHRASE: &str = "correct horse battery staple";
    const GOLDEN_V1: &str = r#"{"version":1,"kdf":{"algorithm":"argon2id","version":19,"memory_kib":19456,"time_cost":2,"parallelism":1,"output_bytes":32},"salt":"AwMDAwMDAwMDAwMDAwMDAw==","nonce":"BQUFBQUFBQUFBQUF","ciphertext":"xTxpw8tMrwHW9L/U+LCyFsOVjYw+c+kqoBtPdv6tvw/bAK9Ffkl3fv5CTb1hwiLp"}"#;
    const KNOWN_DERIVED_KEY: [u8; KEY_BYTES] = [
        0xc3, 0xf9, 0x0a, 0x8a, 0xcd, 0x32, 0xe5, 0x6a, 0x82, 0x8c, 0x23, 0x7c, 0x35, 0x23, 0xd6,
        0x7d, 0x5b, 0x2b, 0x04, 0x58, 0x62, 0xdf, 0x43, 0x8c, 0xfb, 0x1c, 0x9d, 0x44, 0x8c, 0x6f,
        0x37, 0x0e,
    ];

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn authentication_is_honestly_process_local() {
        let dir = private_tempdir();
        let path = dir.path().join("key.json");
        let mut key = KeyLifecycle::new(&path);
        assert_eq!(key.status().unwrap(), KeyStatus::NotInitialized);
        key.setup(PASSPHRASE, PASSPHRASE).unwrap();
        assert_eq!(key.status().unwrap(), KeyStatus::AuthenticatedThisProcess);
        assert_eq!(
            KeyLifecycle::new(&path).status().unwrap(),
            KeyStatus::Locked
        );
        key.lock();
        assert_eq!(key.status().unwrap(), KeyStatus::Locked);
        key.verify_passphrase(PASSPHRASE).unwrap();
        assert!(key.is_authenticated());
    }

    #[test]
    fn confirmation_and_strength_fail_without_artifacts() {
        let dir = private_tempdir();
        let path = dir.path().join("nested/key.json");
        for (passphrase, confirmation, expected) in [
            (
                "short",
                "short",
                "passphrase must contain at least 12 characters",
            ),
            (
                PASSPHRASE,
                "different phrase",
                "passphrase confirmation did not match",
            ),
        ] {
            let error = KeyLifecycle::new(&path)
                .setup(passphrase, confirmation)
                .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert!(!path.exists());
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    assert_eq!(fs::read_dir(parent).unwrap().count(), 0);
                }
            }
        }
    }

    #[test]
    fn wrong_passphrase_does_not_authenticate_or_leak() {
        let dir = private_tempdir();
        let path = dir.path().join("key.json");
        let mut key = KeyLifecycle::new(&path);
        key.setup(PASSPHRASE, PASSPHRASE).unwrap();
        key.lock();
        assert!(key.verify_passphrase("wrong").is_err());
        assert!(!key.is_authenticated());
        assert!(!fs::read_to_string(path).unwrap().contains(PASSPHRASE));
    }

    #[test]
    fn kdf_contract_is_explicit_and_untrusted_costs_are_rejected() {
        let key = [7_u8; KEY_BYTES];
        let salt = [3_u8; SALT_BYTES];
        let nonce = [5_u8; NONCE_BYTES];
        let stored = encrypt_key(&key, PASSPHRASE, &salt, &nonce).unwrap();
        assert_eq!(stored.kdf, KdfContract::supported());

        for mutation in [
            ("algorithm", serde_json::json!("scrypt")),
            ("version", serde_json::json!(18)),
            ("memory_kib", serde_json::json!(u32::MAX)),
            ("time_cost", serde_json::json!(u32::MAX)),
            ("parallelism", serde_json::json!(u32::MAX)),
            ("output_bytes", serde_json::json!(u32::MAX)),
        ] {
            let mut value = serde_json::to_value(&stored).unwrap();
            value["kdf"][mutation.0] = mutation.1;
            let altered: StoredKey = serde_json::from_value(value).unwrap();
            assert!(matches!(altered.kdf.params(), Err(KeyError::InvalidFile)));
        }
    }

    #[test]
    fn golden_v1_envelope_remains_readable() {
        let dir = private_tempdir();
        let path = dir.path().join("key.json");
        let derived = derive_key(
            PASSPHRASE,
            &[3_u8; SALT_BYTES],
            KdfContract::supported().params().unwrap(),
        )
        .unwrap();
        assert_eq!(*derived, KNOWN_DERIVED_KEY);
        crate::secure_fs::install_new_file(&path, GOLDEN_V1.as_bytes()).unwrap();
        let mut lifecycle = KeyLifecycle::new(path);
        lifecycle.verify_passphrase(PASSPHRASE).unwrap();
        assert!(lifecycle.is_authenticated());
    }

    #[test]
    fn every_envelope_field_and_encoding_boundary_is_authenticated() {
        fn rejection(value: &serde_json::Value) -> KeyError {
            let dir = private_tempdir();
            let path = dir.path().join("key.json");
            fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            KeyLifecycle::new(path)
                .verify_passphrase(PASSPHRASE)
                .unwrap_err()
        }

        let golden: serde_json::Value = serde_json::from_str(GOLDEN_V1).unwrap();
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("salt", serde_json::json!("%%%")),
            (
                "salt",
                serde_json::json!(B64.encode([3_u8; SALT_BYTES - 1])),
            ),
            ("nonce", serde_json::json!("%%%")),
            (
                "nonce",
                serde_json::json!(B64.encode([5_u8; NONCE_BYTES - 1])),
            ),
            ("ciphertext", serde_json::json!("%%%")),
            (
                "ciphertext",
                serde_json::json!(B64.encode([0_u8; KEY_BYTES + TAG_BYTES - 1])),
            ),
        ] {
            let mut altered = golden.clone();
            altered[field] = value;
            assert!(matches!(rejection(&altered), KeyError::InvalidFile));
        }

        let mut altered_ciphertext = golden.clone();
        let mut ciphertext = B64
            .decode(altered_ciphertext["ciphertext"].as_str().unwrap())
            .unwrap();
        ciphertext[0] ^= 1;
        altered_ciphertext["ciphertext"] = serde_json::json!(B64.encode(ciphertext));
        assert!(matches!(
            rejection(&altered_ciphertext),
            KeyError::InvalidPassphrase
        ));

        for location in [None, Some("kdf")] {
            let mut unknown = golden.clone();
            if let Some(object) = location {
                unknown[object]["unknown"] = serde_json::json!(true);
            } else {
                unknown["unknown"] = serde_json::json!(true);
            }
            assert!(matches!(rejection(&unknown), KeyError::InvalidFile));
        }

        let stored: StoredKey = serde_json::from_str(GOLDEN_V1).unwrap();
        let derived = derive_key(
            PASSPHRASE,
            &[3_u8; SALT_BYTES],
            stored.kdf.params().unwrap(),
        )
        .unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&*derived).unwrap();
        let nonce = B64.decode(stored.nonce).unwrap();
        let mut sealed = B64.decode(stored.ciphertext).unwrap();
        let tag = sealed.split_off(KEY_BYTES);
        assert!(
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    b"mg-contacts user-held key v2",
                    &mut sealed,
                    chacha20poly1305::Tag::from_slice(&tag),
                )
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn key_and_parent_are_private() {
        use std::os::unix::fs::MetadataExt;
        let dir = private_tempdir();
        let path = dir.path().join("nested/key.json");
        let mut key = KeyLifecycle::new(&path);
        key.setup(PASSPHRASE, PASSPHRASE).unwrap();
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_key_and_parent_are_rejected() {
        let dir = private_tempdir();
        let target = dir.path().join("target");
        fs::write(&target, b"x").unwrap();
        let key_path = dir.path().join("key.json");
        std::os::unix::fs::symlink(&target, &key_path).unwrap();
        assert!(
            KeyLifecycle::new(&key_path)
                .setup(PASSPHRASE, PASSPHRASE)
                .is_err()
        );

        let attacker = dir.path().join("attacker");
        fs::create_dir(&attacker).unwrap();
        let linked_parent = dir.path().join("linked");
        std::os::unix::fs::symlink(&attacker, &linked_parent).unwrap();
        let mut key = KeyLifecycle::new(linked_parent.join("key.json"));
        assert!(key.setup(PASSPHRASE, PASSPHRASE).is_err());
        assert!(!attacker.join("key.json").exists());
    }
}
