//! Encrypted, restart-persistent contact records.

use std::{collections::BTreeMap, fs::OpenOptions, io::Write, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    audit::{
        ActorId, AuditAction, AuditEventId, AuditTrail, NewAuditEvent, Provenance, RecordId,
        TimestampMillis,
    },
    envelope::{EncryptedFieldEnvelope, EnvelopeError, FieldContext, FieldId, FieldPurpose},
    keyring::KeyLifecycle,
    privacy::{PrivacyClassification, PrivacyDomain},
};

const STORE_VERSION: u8 = 1;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ContactError {
    #[error("contact store could not be read")]
    Read(#[source] std::io::Error),
    #[error("contact store could not be written")]
    Write(#[source] std::io::Error),
    #[error("contact store is malformed")]
    Malformed,
    #[error("contact already exists")]
    AlreadyExists,
    #[error("contact was not found")]
    NotFound,
    #[error("contact is deleted")]
    Deleted,
    #[error("contact identifier is invalid")]
    InvalidId,
    #[error("contact field is invalid")]
    InvalidField,
    #[error("contact encryption failed")]
    Encryption(#[from] EnvelopeError),
    #[error("contact audit failed")]
    Audit(#[from] crate::audit::AuditError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredContact {
    version: u8,
    id: RecordId,
    name: EncryptedFieldEnvelope,
    email: EncryptedFieldEnvelope,
    phone: EncryptedFieldEnvelope,
    deleted: bool,
    revision: u64,
    audit: AuditTrail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    pub id: String,
    pub name: String,
    pub email: String,
    pub phone: String,
    pub revision: u64,
    pub deleted: bool,
}

pub fn create(
    key: &KeyLifecycle,
    path: &Path,
    id: &str,
    name: &str,
    email: &str,
    phone: &str,
) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let records = load(path)?;
    if records.iter().any(|r| r.id == record_id && !r.deleted) {
        return Err(ContactError::AlreadyExists);
    }
    let record = build_record(
        key,
        &record_id,
        name,
        email,
        phone,
        false,
        1,
        AuditAction::Created,
        1,
    )?;
    append(path, &record)?;
    view(key, &record)
}

pub fn update(
    key: &KeyLifecycle,
    path: &Path,
    id: &str,
    name: &str,
    email: &str,
    phone: &str,
) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let records = load(path)?;
    let current = latest(&records, &record_id).ok_or(ContactError::NotFound)?;
    if current.deleted {
        return Err(ContactError::Deleted);
    }
    let revision = current
        .revision
        .checked_add(1)
        .ok_or(ContactError::Malformed)?;
    let sequence = u64::try_from(current.audit.entries().len())
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or(ContactError::Malformed)?;
    let record = build_record(
        key,
        &record_id,
        name,
        email,
        phone,
        false,
        revision,
        AuditAction::Updated,
        sequence,
    )?;
    append(path, &record)?;
    view(key, &record)
}

pub fn soft_delete(key: &KeyLifecycle, path: &Path, id: &str) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let records = load(path)?;
    let current = latest(&records, &record_id).ok_or(ContactError::NotFound)?;
    if current.deleted {
        return Err(ContactError::Deleted);
    }
    let name = decrypt(key, &record_id, "name", &current.name)?;
    let email = decrypt(key, &record_id, "email", &current.email)?;
    let phone = decrypt(key, &record_id, "phone", &current.phone)?;
    let revision = current
        .revision
        .checked_add(1)
        .ok_or(ContactError::Malformed)?;
    let sequence = u64::try_from(current.audit.entries().len())
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or(ContactError::Malformed)?;
    let record = build_record(
        key,
        &record_id,
        &name,
        &email,
        &phone,
        true,
        revision,
        AuditAction::SoftDeleted,
        sequence,
    )?;
    append(path, &record)?;
    view(key, &record)
}

pub fn get(key: &KeyLifecycle, path: &Path, id: &str) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let records = load(path)?;
    let record = latest(&records, &record_id).ok_or(ContactError::NotFound)?;
    if record.deleted {
        return Err(ContactError::Deleted);
    }
    view(key, record)
}

pub fn list(key: &KeyLifecycle, path: &Path) -> Result<Vec<ContactView>, ContactError> {
    let mut latest_records = BTreeMap::new();
    for record in load(path)? {
        latest_records.insert(record.id.as_str().to_owned(), record);
    }
    latest_records
        .values()
        .filter(|r| !r.deleted)
        .map(|r| view(key, r))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    key: &KeyLifecycle,
    id: &RecordId,
    name: &str,
    email: &str,
    phone: &str,
    deleted: bool,
    revision: u64,
    action: AuditAction,
    sequence: u64,
) -> Result<StoredContact, ContactError> {
    if name.is_empty() || email.is_empty() || phone.is_empty() {
        return Err(ContactError::InvalidField);
    }
    let mut audit = AuditTrail::new(id.clone());
    let event_id = AuditEventId::parse(format!("{}:{sequence}", id.as_str()))
        .map_err(|_| ContactError::InvalidField)?;
    let actor = ActorId::parse("local-user").map_err(|_| ContactError::InvalidField)?;
    let provenance = Provenance::new("mg-contacts", format!("contact:{}", id.as_str()))?;
    audit.append(NewAuditEvent::new(
        event_id,
        now(),
        actor,
        action,
        provenance,
    ))?;
    Ok(StoredContact {
        version: STORE_VERSION,
        id: id.clone(),
        name: encrypt(key, id, "name", name)?,
        email: encrypt(key, id, "email", email)?,
        phone: encrypt(key, id, "phone", phone)?,
        deleted,
        revision,
        audit,
    })
}

fn context(id: &RecordId, field: &str) -> Result<FieldContext, ContactError> {
    Ok(FieldContext::new(
        id.clone(),
        FieldId::parse(field).map_err(|_| ContactError::InvalidField)?,
        PrivacyClassification::default_for(PrivacyDomain::OrdinaryContact),
        FieldPurpose::RecordField,
    ))
}
fn encrypt(
    key: &KeyLifecycle,
    id: &RecordId,
    field: &str,
    value: &str,
) -> Result<EncryptedFieldEnvelope, ContactError> {
    Ok(key.encrypt_field(&context(id, field)?, value.as_bytes())?)
}
fn decrypt(
    key: &KeyLifecycle,
    id: &RecordId,
    field: &str,
    value: &EncryptedFieldEnvelope,
) -> Result<Zeroizing<String>, ContactError> {
    let bytes = key.decrypt_field(&context(id, field)?, value)?;
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| ContactError::Malformed)
}
fn view(key: &KeyLifecycle, record: &StoredContact) -> Result<ContactView, ContactError> {
    Ok(ContactView {
        id: record.id.as_str().to_owned(),
        name: decrypt(key, &record.id, "name", &record.name)?.to_string(),
        email: decrypt(key, &record.id, "email", &record.email)?.to_string(),
        phone: decrypt(key, &record.id, "phone", &record.phone)?.to_string(),
        revision: record.revision,
        deleted: record.deleted,
    })
}
fn latest<'a>(records: &'a [StoredContact], id: &RecordId) -> Option<&'a StoredContact> {
    records.iter().rev().find(|r| &r.id == id)
}
fn load(path: &Path) -> Result<Vec<StoredContact>, ContactError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path).map_err(ContactError::Read)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ContactError::Malformed);
    }
    bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| ContactError::Malformed))
        .collect()
}
fn append(path: &Path, record: &StoredContact) -> Result<(), ContactError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(ContactError::Write)?;
        #[cfg(unix)]
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(ContactError::Write)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(ContactError::Write)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(ContactError::Write)?;
    let bytes = serde_json::to_vec(record).map_err(|_| ContactError::Malformed)?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(ContactError::Write)
}
fn now() -> TimestampMillis {
    TimestampMillis::new(
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(i64::MAX),
    )
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    const PASSPHRASE: &str = "correct horse battery staple";
    #[test]
    fn encrypted_contact_survives_restart_and_soft_delete() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let key_path = data.join("keyring.json");
        let store_path = data.join("contacts.log");
        let mut key = KeyLifecycle::new(&key_path);
        key.setup(PASSPHRASE, PASSPHRASE).unwrap();
        create(
            &key,
            &store_path,
            "person-1",
            "Ada Lovelace",
            "ada@example.test",
            "+1-555-0100",
        )
        .unwrap();
        let ciphertext = fs::read(&store_path).unwrap();
        assert!(
            !ciphertext
                .windows(b"Ada Lovelace".len())
                .any(|w| w == b"Ada Lovelace")
        );
        drop(key);
        let mut reopened = KeyLifecycle::new(&key_path);
        reopened.verify_passphrase(PASSPHRASE).unwrap();
        assert_eq!(
            get(&reopened, &store_path, "person-1").unwrap().name,
            "Ada Lovelace"
        );
        update(
            &reopened,
            &store_path,
            "person-1",
            "Ada Byron",
            "ada@example.test",
            "+1-555-0101",
        )
        .unwrap();
        assert_eq!(get(&reopened, &store_path, "person-1").unwrap().revision, 2);
        soft_delete(&reopened, &store_path, "person-1").unwrap();
        assert!(matches!(
            get(&reopened, &store_path, "person-1"),
            Err(ContactError::Deleted)
        ));
        assert!(list(&reopened, &store_path).unwrap().is_empty());
    }
    #[test]
    fn wrong_passphrase_cannot_read_contact() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let key_path = data.join("keyring.json");
        let store_path = data.join("contacts.log");
        let mut key = KeyLifecycle::new(&key_path);
        key.setup(PASSPHRASE, PASSPHRASE).unwrap();
        create(
            &key,
            &store_path,
            "person-1",
            "Ada",
            "ada@example.test",
            "phone",
        )
        .unwrap();
        key.lock();
        assert!(matches!(
            get(&key, &store_path, "person-1"),
            Err(ContactError::Encryption(EnvelopeError::KeyLocked))
        ));
    }
}
