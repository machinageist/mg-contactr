//! Encrypted, restart-persistent contact records.

use std::path::Path;

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
    store::{Store, StoreError, StoredContact},
};

const STORE_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum ContactError {
    #[error("contact store could not be read")]
    Read(#[source] std::io::Error),
    #[error("contact store could not be written")]
    Write(#[source] std::io::Error),
    #[error("contact store is malformed")]
    Malformed,
    #[error("contact store was written by a newer mg-contacts")]
    FutureStore,
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

// A store failure met while reading; the reason stays inside the error, never in output
fn read_failure(error: StoreError) -> ContactError {
    match error {
        StoreError::Malformed => ContactError::Malformed,
        StoreError::FutureSchema => ContactError::FutureStore,
        other => ContactError::Read(other.into_io()),
    }
}

// The same failure met while writing, so the two stay distinguishable to the caller
fn write_failure(error: StoreError) -> ContactError {
    match error {
        StoreError::Malformed => ContactError::Malformed,
        StoreError::FutureSchema => ContactError::FutureStore,
        other => ContactError::Write(other.into_io()),
    }
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

// Add a contact, or bring a soft-deleted id back
pub fn create(
    key: &KeyLifecycle,
    path: &Path,
    id: &str,
    name: &str,
    email: &str,
    phone: &str,
) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let store = Store::open(path).map_err(write_failure)?;
    // Only the newest revision says whether this id is in use. Scanning every
    // record found the pre-delete revisions, which still carry deleted = false,
    // so a soft-deleted id could never be created again.
    let previous = store.latest(&record_id).map_err(read_failure)?;
    let previous = previous.as_ref();
    if previous.is_some_and(|r| !r.deleted) {
        return Err(ContactError::AlreadyExists);
    }
    // Recreating an id continues its trail; the deletion stays on the record
    let revision = previous.map_or(Ok(1), |r| {
        r.revision.checked_add(1).ok_or(ContactError::Malformed)
    })?;
    let record = build_record(
        key,
        &record_id,
        name,
        email,
        phone,
        false,
        revision,
        AuditAction::Created,
        previous.map(|r| &r.audit),
    )?;
    store.append(&record).map_err(write_failure)?;
    view(key, &record)
}

// Replace a contact's fields with a new revision
pub fn update(
    key: &KeyLifecycle,
    path: &Path,
    id: &str,
    name: &str,
    email: &str,
    phone: &str,
) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let store = Store::open(path).map_err(write_failure)?;
    let current = store
        .latest(&record_id)
        .map_err(read_failure)?
        .ok_or(ContactError::NotFound)?;
    if current.deleted {
        return Err(ContactError::Deleted);
    }
    let revision = current
        .revision
        .checked_add(1)
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
        Some(&current.audit),
    )?;
    store.append(&record).map_err(write_failure)?;
    view(key, &record)
}

// Retire a contact, keeping every revision it already had
pub fn soft_delete(key: &KeyLifecycle, path: &Path, id: &str) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let store = Store::open(path).map_err(write_failure)?;
    let current = store
        .latest(&record_id)
        .map_err(read_failure)?
        .ok_or(ContactError::NotFound)?;
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
    let record = build_record(
        key,
        &record_id,
        &name,
        &email,
        &phone,
        true,
        revision,
        AuditAction::SoftDeleted,
        Some(&current.audit),
    )?;
    store.append(&record).map_err(write_failure)?;
    view(key, &record)
}

// Read one live contact
pub fn get(key: &KeyLifecycle, path: &Path, id: &str) -> Result<ContactView, ContactError> {
    let record_id = RecordId::parse(id).map_err(|_| ContactError::InvalidId)?;
    let store = Store::open(path).map_err(read_failure)?;
    let record = store
        .latest(&record_id)
        .map_err(read_failure)?
        .ok_or(ContactError::NotFound)?;
    if record.deleted {
        return Err(ContactError::Deleted);
    }
    view(key, &record)
}

// Read every live contact, in id order
pub fn list(key: &KeyLifecycle, path: &Path) -> Result<Vec<ContactView>, ContactError> {
    Store::open(path)
        .map_err(read_failure)?
        .latest_all()
        .map_err(read_failure)?
        .iter()
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
    previous: Option<&AuditTrail>,
) -> Result<StoredContact, ContactError> {
    if name.is_empty() || email.is_empty() || phone.is_empty() {
        return Err(ContactError::InvalidField);
    }
    // The trail is this record's whole history, so it continues from the last
    // revision. Starting a fresh one gave every event sequence 1, made every
    // update and delete reuse the id "<record>:2", and left previous_event_id
    // empty so nothing linked to what came before it.
    let mut audit = previous.map_or_else(|| AuditTrail::new(id.clone()), Clone::clone);
    let sequence = u64::try_from(audit.entries().len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or(ContactError::Malformed)?;
    let event_id = AuditEventId::parse(format!("{}:{sequence}", id.as_str()))
        .map_err(|_| ContactError::InvalidField)?;
    let actor = ActorId::parse("local-user").map_err(|_| ContactError::InvalidField)?;
    let provenance = Provenance::new("mg-contacts", format!("contact:{}", id.as_str()))?;
    audit.append(NewAuditEvent::new(
        event_id,
        next_timestamp(&audit),
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
// A trail refuses an event whose timestamp does not advance, and the clock only
// counts whole milliseconds — two edits inside one of them are entirely ordinary.
// Step past the last event rather than refusing an edit the user legitimately made.
fn next_timestamp(audit: &AuditTrail) -> TimestampMillis {
    let reading = now();
    audit.entries().last().map_or(reading, |last| {
        let floor = last.timestamp().get().saturating_add(1);
        TimestampMillis::new(reading.get().max(floor))
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;
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
        let store_path = data.join("contacts.sqlite");
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
    // Set up a keyring and an empty store, the way every test here needs one
    fn scratch(dir: &tempfile::TempDir) -> (KeyLifecycle, std::path::PathBuf) {
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let mut key = KeyLifecycle::new(data.join("keyring.json"));
        key.setup(PASSPHRASE, PASSPHRASE).unwrap();
        (key, data.join("contacts.sqlite"))
    }

    #[test]
    fn a_soft_deleted_id_can_be_used_again() {
        // The store is append-only, so the pre-delete revisions still say
        // deleted = false. Reading those instead of the newest one bricked the id.
        let dir = tempdir().unwrap();
        let (key, store) = scratch(&dir);
        create(&key, &store, "person-1", "Ada", "ada@example.test", "phone").unwrap();
        update(
            &key,
            &store,
            "person-1",
            "Ada B",
            "ada@example.test",
            "phone",
        )
        .unwrap();
        soft_delete(&key, &store, "person-1").unwrap();

        let reborn = create(
            &key,
            &store,
            "person-1",
            "Grace",
            "grace@example.test",
            "phone",
        )
        .expect("a deleted id is free to use again");
        assert_eq!(reborn.name, "Grace");
        assert!(!reborn.deleted);
        assert_eq!(get(&key, &store, "person-1").unwrap().name, "Grace");
        assert_eq!(list(&key, &store).unwrap().len(), 1);
    }

    #[test]
    fn a_live_id_is_still_refused() {
        let dir = tempdir().unwrap();
        let (key, store) = scratch(&dir);
        create(&key, &store, "person-1", "Ada", "ada@example.test", "phone").unwrap();
        assert!(matches!(
            create(&key, &store, "person-1", "Grace", "g@example.test", "phone"),
            Err(ContactError::AlreadyExists)
        ));
    }

    #[test]
    fn the_audit_trail_accumulates_across_revisions() {
        let dir = tempdir().unwrap();
        let (key, store) = scratch(&dir);
        create(&key, &store, "person-1", "Ada", "ada@example.test", "phone").unwrap();
        update(
            &key,
            &store,
            "person-1",
            "Ada B",
            "ada@example.test",
            "phone",
        )
        .unwrap();
        soft_delete(&key, &store, "person-1").unwrap();

        let id = RecordId::parse("person-1").unwrap();
        let newest = Store::open(&store).unwrap().latest(&id).unwrap().unwrap();
        let entries = newest.audit.entries();

        assert_eq!(entries.len(), 3, "every revision keeps the ones before it");
        assert_eq!(
            entries.iter().map(AuditEvent::sequence).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // Each event used to be "<id>:2"; they have to be distinct to identify anything
        let ids: Vec<_> = entries.iter().map(|e| e.event_id().as_str()).collect();
        assert_eq!(ids, vec!["person-1:1", "person-1:2", "person-1:3"]);
        assert_eq!(
            entries.iter().map(AuditEvent::action).collect::<Vec<_>>(),
            vec![
                AuditAction::Created,
                AuditAction::Updated,
                AuditAction::SoftDeleted
            ]
        );
        // The chain has to link, or the trail cannot be walked backwards
        assert!(entries[0].previous_event_id().is_none());
        for pair in entries.windows(2) {
            assert_eq!(
                pair[1].previous_event_id().map(AuditEventId::as_str),
                Some(pair[0].event_id().as_str())
            );
        }
    }

    #[test]
    fn edits_inside_one_millisecond_still_advance_the_trail() {
        // The clock counts whole milliseconds and a trail refuses an event that
        // does not advance, so back-to-back edits must not be refused.
        let dir = tempdir().unwrap();
        let (key, store) = scratch(&dir);
        create(&key, &store, "person-1", "Ada", "ada@example.test", "phone").unwrap();
        for round in 0..12 {
            update(
                &key,
                &store,
                "person-1",
                &format!("Ada {round}"),
                "ada@example.test",
                "phone",
            )
            .expect("a fast edit is still a legitimate edit");
        }
        let id = RecordId::parse("person-1").unwrap();
        let newest = Store::open(&store).unwrap().latest(&id).unwrap().unwrap();
        let entries = newest.audit.entries();
        assert_eq!(entries.len(), 13);
        for pair in entries.windows(2) {
            assert!(
                pair[1].timestamp() > pair[0].timestamp(),
                "timestamps must be strictly increasing"
            );
        }
    }

    #[test]
    fn wrong_passphrase_cannot_read_contact() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let key_path = data.join("keyring.json");
        let store_path = data.join("contacts.sqlite");
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
