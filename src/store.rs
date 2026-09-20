// Author: Jeff
// Date: 2026-09-19
// Description: The one SQLite file holding mg-contacts' encrypted contact revisions
// Notes: Only ciphertext and the metadata the old JSON-lines log already left in the clear live
//        here — record id, revision, deleted flag, audit trail. Field values arrive already
//        sealed by envelope.rs and are stored as the exact bytes serde writes for them, so a
//        plaintext field never reaches the database, its WAL, or a temporary table. The file is
//        0600 inside a 0700 directory, and SQLite gives -wal and -shm the database file's own
//        mode. Migrations are append-only and recorded, the grammar the rest of the suite uses

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::audit::{AuditTrail, RecordId};
use crate::envelope::EncryptedFieldEnvelope;
use crate::secure_fs;

// ── Schema ──
// Append-only: a shipped migration is never edited, only followed by another

const MIGRATIONS: &[&str] = &["\
CREATE TABLE contact_revisions (sequence INTEGER PRIMARY KEY, version INTEGER NOT NULL, \
  record_id TEXT NOT NULL, revision INTEGER NOT NULL, \
  deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)), \
  name BLOB NOT NULL, email BLOB NOT NULL, phone BLOB NOT NULL, audit BLOB NOT NULL, \
  UNIQUE(record_id, revision)); \
CREATE INDEX contact_revisions_by_record ON contact_revisions(record_id, sequence);"];

const MIGRATION_LEDGER: &str =
    "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)";
const COUNT_APPLIED: &str = "SELECT COUNT(*) FROM schema_migrations";
const RECORD_APPLIED: &str = "INSERT INTO schema_migrations(version) VALUES (?1)";
const REVISION_COLUMNS: &str = "version,record_id,revision,deleted,name,email,phone,audit";
const INSERT_REVISION: &str = "INSERT INTO contact_revisions(version,record_id,revision,deleted,name,email,phone,audit) \
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)";
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const PRIVATE_FILE_MODE: u32 = 0o600;
const WAL_JOURNAL_MODE: &str = "wal";

// ── The stored record ──
// The revision as it sits in one row: sealed fields, and the metadata that was never sealed

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredContact {
    pub(crate) version: u8,
    pub(crate) id: RecordId,
    pub(crate) name: EncryptedFieldEnvelope,
    pub(crate) email: EncryptedFieldEnvelope,
    pub(crate) phone: EncryptedFieldEnvelope,
    pub(crate) deleted: bool,
    pub(crate) revision: u64,
    pub(crate) audit: AuditTrail,
}

// ── Failures ──
// Every message is about the store itself; a path or a value never appears in one

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("contact store could not be used")]
    Sqlite(#[from] rusqlite::Error),
    #[error("contact store file is unavailable")]
    Io(#[source] std::io::Error),
    #[error("contact store row is malformed")]
    Malformed,
    #[error("contact store was written by a newer mg-contacts")]
    FutureSchema,
    #[error("contact store could not use write-ahead logging")]
    NotWal,
}

impl StoreError {
    // Reduce a store failure to the io error the contact layer carries
    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            Self::Io(error) => error,
            other => std::io::Error::other(other),
        }
    }
}

// ── The store ──

pub(crate) struct Store {
    connection: Connection,
}

impl Store {
    // Open (creating) the database and bring its schema up to date
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::Io(std::io::ErrorKind::InvalidInput.into()))?;
        secure_fs::ensure_private_dir(parent).map_err(|error| StoreError::Io(error.into_io()))?;
        // Own the file before SQLite does, so it is 0600 from birth; an existing one is
        // accepted only on the terms secure_fs already applies to the key file
        match secure_fs::regular_file_exists(path) {
            Ok(true) => {}
            Ok(false) => create_private_file(path)?,
            Err(error) => return Err(StoreError::Io(error.into_io())),
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case(WAL_JOURNAL_MODE) {
            return Err(StoreError::NotWal);
        }
        migrate(&mut connection)?;
        Ok(Self { connection })
    }

    // The newest revision of one record, which alone says whether the id is in use
    pub(crate) fn latest(&self, id: &RecordId) -> Result<Option<StoredContact>, StoreError> {
        let sql = format!(
            "SELECT {REVISION_COLUMNS} FROM contact_revisions WHERE record_id=?1 \
             ORDER BY sequence DESC LIMIT 1"
        );
        let mut statement = self.connection.prepare(&sql)?;
        let mut rows = statement.query(params![id.as_str()])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        contact_from_row(row).map(Some)
    }

    // The newest revision of every record, in record-id order
    pub(crate) fn latest_all(&self) -> Result<Vec<StoredContact>, StoreError> {
        let sql = format!(
            "SELECT {REVISION_COLUMNS} FROM contact_revisions WHERE sequence IN \
             (SELECT MAX(sequence) FROM contact_revisions GROUP BY record_id) ORDER BY record_id"
        );
        let mut statement = self.connection.prepare(&sql)?;
        let mut rows = statement.query([])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            records.push(contact_from_row(row)?);
        }
        Ok(records)
    }

    // Add one revision; history is never rewritten
    // DEBT: reading the newest revision and adding the next are two statements, so a second
    // writer is caught by UNIQUE(record_id, revision) rather than serialised behind it
    pub(crate) fn append(&self, record: &StoredContact) -> Result<(), StoreError> {
        insert(&self.connection, record)
    }
}

// ── Opening ──

// Create the empty database file privately; SQLite reads -wal and -shm modes from it
fn create_private_file(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_FILE_MODE);
    options.open(path).map_err(StoreError::Io)?;
    // A narrow umask can only take bits away, so say the mode outright
    #[cfg(unix)]
    std::fs::set_permissions(
        path,
        std::os::unix::fs::PermissionsExt::from_mode(PRIVATE_FILE_MODE),
    )
    .map_err(StoreError::Io)?;
    Ok(())
}

// Apply every migration this build knows that the ledger has not recorded yet
fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATION_LEDGER)?;
    let applied: i64 = transaction.query_row(COUNT_APPLIED, [], |row| row.get(0))?;
    let applied = usize::try_from(applied).map_err(|_| StoreError::Malformed)?;
    if applied > MIGRATIONS.len() {
        return Err(StoreError::FutureSchema);
    }
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
        let version = i64::try_from(index).map_err(|_| StoreError::Malformed)? + 1;
        transaction.execute_batch(sql)?;
        transaction.execute(RECORD_APPLIED, params![version])?;
    }
    transaction.commit()?;
    Ok(())
}

// ── Columns ──

// Add one revision row through whichever connection or transaction is open
fn insert(connection: &Connection, record: &StoredContact) -> Result<(), StoreError> {
    connection.execute(
        INSERT_REVISION,
        params![
            i64::from(record.version),
            record.id.as_str(),
            i64::try_from(record.revision).map_err(|_| StoreError::Malformed)?,
            i64::from(record.deleted),
            to_column(&record.name)?,
            to_column(&record.email)?,
            to_column(&record.phone)?,
            to_column(&record.audit)?,
        ],
    )?;
    Ok(())
}

// Read one revision row back into the record it holds
fn contact_from_row(row: &rusqlite::Row<'_>) -> Result<StoredContact, StoreError> {
    let version: i64 = row.get(0)?;
    let id: String = row.get(1)?;
    let revision: i64 = row.get(2)?;
    let deleted: i64 = row.get(3)?;
    Ok(StoredContact {
        version: u8::try_from(version).map_err(|_| StoreError::Malformed)?,
        id: RecordId::parse(id).map_err(|_| StoreError::Malformed)?,
        name: from_column(&row.get::<_, Vec<u8>>(4)?)?,
        email: from_column(&row.get::<_, Vec<u8>>(5)?)?,
        phone: from_column(&row.get::<_, Vec<u8>>(6)?)?,
        deleted: deleted != 0,
        revision: u64::try_from(revision).map_err(|_| StoreError::Malformed)?,
        audit: from_column(&row.get::<_, Vec<u8>>(7)?)?,
    })
}

// Serialize a sealed envelope or an audit trail into the bytes its column holds
fn to_column<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|_| StoreError::Malformed)
}

// Read a column back, with the same validation the log lines were held to
fn from_column<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Malformed)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        ActorId, AuditAction, AuditEventId, NewAuditEvent, Provenance, TimestampMillis,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    // A stand-in for a sealed field: the store only ever moves these bytes around
    fn sealed(marker: u8) -> EncryptedFieldEnvelope {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "nonce": vec![marker; 12],
            "ciphertext": vec![marker; 24],
            "tag": vec![marker; 16],
        }))
        .unwrap()
    }

    // A trail with one event per revision, the shape contact.rs writes
    fn trail(id: &RecordId, events: u64) -> AuditTrail {
        let mut trail = AuditTrail::new(id.clone());
        for sequence in 1..=events {
            trail
                .append(NewAuditEvent::new(
                    AuditEventId::parse(format!("{}:{sequence}", id.as_str())).unwrap(),
                    TimestampMillis::new(1_725_000_000_000 + i64::try_from(sequence).unwrap()),
                    ActorId::parse("local-user").unwrap(),
                    AuditAction::Created,
                    Provenance::new("mg-contacts", format!("contact:{}", id.as_str())).unwrap(),
                ))
                .unwrap();
        }
        trail
    }

    fn record(id: &str, revision: u64, deleted: bool) -> StoredContact {
        let id = RecordId::parse(id).unwrap();
        StoredContact {
            version: 1,
            audit: trail(&id, revision),
            id,
            name: sealed(1),
            email: sealed(2),
            phone: sealed(3),
            deleted,
            revision,
        }
    }

    // A private directory with a database path inside it, the way the app lays one out
    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("mg-contacts/contacts.sqlite");
        (root, path)
    }

    #[test]
    fn an_empty_database_migrates_once_and_reopens_unchanged() {
        let (_root, path) = scratch();
        let store = Store::open(&path).unwrap();
        let applied: i64 = store
            .connection
            .query_row(COUNT_APPLIED, [], |row| row.get(0))
            .unwrap();
        assert_eq!(usize::try_from(applied).unwrap(), MIGRATIONS.len());
        drop(store);

        let store = Store::open(&path).unwrap();
        let applied: i64 = store
            .connection
            .query_row(COUNT_APPLIED, [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            usize::try_from(applied).unwrap(),
            MIGRATIONS.len(),
            "a second open applies nothing again"
        );
        let mode: String = store
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert!(mode.eq_ignore_ascii_case(WAL_JOURNAL_MODE));
        let foreign_keys: i64 = store
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn a_ledger_from_a_newer_build_is_refused_rather_than_downgraded() {
        let (_root, path) = scratch();
        let store = Store::open(&path).unwrap();
        let version = i64::try_from(MIGRATIONS.len()).unwrap() + 1;
        store
            .connection
            .execute(RECORD_APPLIED, params![version])
            .unwrap();
        drop(store);
        assert!(
            matches!(Store::open(&path), Err(StoreError::FutureSchema)),
            "a store written by a newer build is left alone"
        );
    }

    #[test]
    fn the_database_and_its_sidecars_are_private_inside_a_private_directory() {
        let (_root, path) = scratch();
        let store = Store::open(&path).unwrap();
        store.append(&record("person-1", 1, false)).unwrap();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for sidecar in ["", "-wal", "-shm"] {
            let mut file = path.clone().into_os_string();
            file.push(sidecar);
            let file = PathBuf::from(file);
            assert!(file.exists(), "a write leaves {sidecar:?} beside the store");
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600,
                "{sidecar:?} must be owner-only"
            );
        }
    }

    #[test]
    fn a_database_someone_else_can_read_is_refused_and_not_repaired() {
        let (_root, path) = scratch();
        drop(Store::open(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::Io(_))));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644,
            "the refusal does not quietly change the file"
        );
    }

    #[test]
    fn revisions_round_trip_and_the_newest_one_wins() {
        let (_root, path) = scratch();
        let store = Store::open(&path).unwrap();
        assert!(
            store
                .latest(&RecordId::parse("person-1").unwrap())
                .unwrap()
                .is_none()
        );
        assert!(store.latest_all().unwrap().is_empty());

        store.append(&record("person-1", 1, false)).unwrap();
        store.append(&record("person-1", 2, false)).unwrap();
        store.append(&record("person-1", 3, true)).unwrap();
        store.append(&record("person-2", 1, false)).unwrap();

        let latest = store
            .latest(&RecordId::parse("person-1").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(latest.revision, 3);
        assert!(latest.deleted, "the tombstoned revision is the newest one");
        assert_eq!(latest.audit.entries().len(), 3, "the trail came back whole");
        assert_eq!(latest.name, sealed(1), "ciphertext is byte-for-byte");
        assert_eq!(
            store.latest(&RecordId::parse("person-9").unwrap()).unwrap(),
            None
        );

        let all = store.latest_all().unwrap();
        assert_eq!(all.len(), 2, "one row per record, not per revision");
        assert_eq!(
            all.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["person-1", "person-2"]
        );
    }

    #[test]
    fn one_revision_of_a_record_cannot_be_written_twice() {
        let (_root, path) = scratch();
        let store = Store::open(&path).unwrap();
        store.append(&record("person-1", 1, false)).unwrap();
        assert!(
            store.append(&record("person-1", 1, false)).is_err(),
            "history is append-only, so a revision number is used once"
        );
    }

    #[test]
    fn a_corrupt_column_is_malformed_rather_than_silently_wrong() {
        let (_root, path) = scratch();
        let store = Store::open(&path).unwrap();
        store.append(&record("person-1", 1, false)).unwrap();
        store
            .connection
            .execute(
                "UPDATE contact_revisions SET name=?1",
                params![b"not json".to_vec()],
            )
            .unwrap();
        assert!(matches!(
            store.latest(&RecordId::parse("person-1").unwrap()),
            Err(StoreError::Malformed)
        ));
        assert!(matches!(store.latest_all(), Err(StoreError::Malformed)));
    }
}
