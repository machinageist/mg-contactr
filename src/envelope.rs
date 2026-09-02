//! Authenticated encrypted field envelopes bound to explicit record context.

use std::fmt;

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::audit::RecordId;
use crate::keyring::KeyLifecycle;
use crate::privacy::PrivacyClassification;

const ENVELOPE_VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_FIELD_ID_BYTES: usize = 256;
const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
const AAD_PREFIX: &[u8] = b"mg-contacts encrypted field envelope v1";

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FieldId(String);

impl FieldId {
    pub fn parse(value: impl Into<String>) -> Result<Self, EnvelopeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_FIELD_ID_BYTES
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(EnvelopeError::InvalidContext);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FieldId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FieldId").field(&self.0).finish()
    }
}

impl<'de> Deserialize<'de> for FieldId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPurpose {
    RecordField,
    Tombstone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldContext {
    record_id: RecordId,
    field_id: FieldId,
    privacy: PrivacyClassification,
    purpose: FieldPurpose,
}

impl FieldContext {
    #[must_use]
    pub const fn new(
        record_id: RecordId,
        field_id: FieldId,
        privacy: PrivacyClassification,
        purpose: FieldPurpose,
    ) -> Self {
        Self {
            record_id,
            field_id,
            privacy,
            purpose,
        }
    }

    #[must_use]
    pub const fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    #[must_use]
    pub const fn field_id(&self) -> &FieldId {
        &self.field_id
    }

    #[must_use]
    pub const fn privacy(&self) -> PrivacyClassification {
        self.privacy
    }

    #[must_use]
    pub const fn purpose(&self) -> FieldPurpose {
        self.purpose
    }

    fn aad(&self) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let privacy =
            serde_json::to_vec(&self.privacy).map_err(|_| EnvelopeError::InvalidContext)?;
        let mut aad = Zeroizing::new(Vec::with_capacity(
            AAD_PREFIX.len()
                + self.record_id.as_str().len()
                + self.field_id.as_str().len()
                + privacy.len()
                + 32,
        ));
        append_component(&mut aad, AAD_PREFIX)?;
        append_component(&mut aad, self.record_id.as_str().as_bytes())?;
        append_component(&mut aad, self.field_id.as_str().as_bytes())?;
        append_component(&mut aad, &privacy)?;
        append_component(
            &mut aad,
            match self.purpose {
                FieldPurpose::RecordField => b"record_field",
                FieldPurpose::Tombstone => b"tombstone",
            },
        )?;
        Ok(aad)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedFieldEnvelope {
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_BYTES],
}

impl EncryptedFieldEnvelope {
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedFieldEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedFieldEnvelope")
            .field("version", &ENVELOPE_VERSION)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    version: u8,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

impl Serialize for EncryptedFieldEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EnvelopeWire {
            version: ENVELOPE_VERSION,
            nonce: self.nonce.to_vec(),
            ciphertext: self.ciphertext.clone(),
            tag: self.tag.to_vec(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedFieldEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EnvelopeWire::deserialize(deserializer)?;
        if wire.version != ENVELOPE_VERSION
            || wire.nonce.len() != NONCE_BYTES
            || wire.tag.len() != TAG_BYTES
            || wire.ciphertext.len() > MAX_CIPHERTEXT_BYTES
        {
            return Err(de::Error::custom("encrypted field envelope is invalid"));
        }
        Ok(Self {
            nonce: wire
                .nonce
                .try_into()
                .map_err(|_| de::Error::custom("encrypted field envelope is invalid"))?,
            ciphertext: wire.ciphertext,
            tag: wire
                .tag
                .try_into()
                .map_err(|_| de::Error::custom("encrypted field envelope is invalid"))?,
        })
    }
}

impl KeyLifecycle {
    pub fn encrypt_field(
        &self,
        context: &FieldContext,
        plaintext: &[u8],
    ) -> Result<EncryptedFieldEnvelope, EnvelopeError> {
        if plaintext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(EnvelopeError::FieldTooLarge);
        }
        let key = self.field_key().ok_or(EnvelopeError::KeyLocked)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| EnvelopeError::EncryptionFailed)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| EnvelopeError::EncryptionFailed)?;
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        let aad = context.aad()?;
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ciphertext)
            .map_err(|_| EnvelopeError::EncryptionFailed)?;
        Ok(EncryptedFieldEnvelope {
            nonce,
            ciphertext: ciphertext.to_vec(),
            tag: tag.into(),
        })
    }

    pub fn decrypt_field(
        &self,
        context: &FieldContext,
        envelope: &EncryptedFieldEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let key = self.field_key().ok_or(EnvelopeError::KeyLocked)?;
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| EnvelopeError::AuthenticationFailed)?;
        let mut plaintext = Zeroizing::new(envelope.ciphertext.clone());
        let aad = context.aad()?;
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&envelope.nonce),
                &aad,
                &mut plaintext,
                Tag::from_slice(&envelope.tag),
            )
            .map_err(|_| EnvelopeError::AuthenticationFailed)?;
        Ok(plaintext)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("encryption key is locked")]
    KeyLocked,
    #[error("encrypted field could not be authenticated")]
    AuthenticationFailed,
    #[error("encrypted field context is invalid")]
    InvalidContext,
    #[error("encrypted field exceeds the size limit")]
    FieldTooLarge,
    #[error("encrypted field encryption failed")]
    EncryptionFailed,
}

fn append_component(target: &mut Vec<u8>, component: &[u8]) -> Result<(), EnvelopeError> {
    let length = u32::try_from(component.len()).map_err(|_| EnvelopeError::InvalidContext)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(component);
    Ok(())
}
