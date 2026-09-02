//! Stable encrypted soft-delete tombstones.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroizing;

use crate::audit::{AuditEventId, RecordId, TimestampMillis};
use crate::envelope::{EncryptedFieldEnvelope, EnvelopeError, FieldContext, FieldId, FieldPurpose};
use crate::keyring::KeyLifecycle;
use crate::privacy::{PrivacyClassification, PrivacyDomain};

const TOMBSTONE_VERSION: u8 = 1;
const TOMBSTONE_FIELD_ID: &str = "tombstone.delete_details";

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedTombstone {
    record_id: RecordId,
    deleted_at: TimestampMillis,
    audit_event_id: AuditEventId,
    details: EncryptedFieldEnvelope,
}

impl EncryptedTombstone {
    pub fn seal(
        key: &KeyLifecycle,
        record_id: RecordId,
        deleted_at: TimestampMillis,
        audit_event_id: AuditEventId,
        details: &[u8],
    ) -> Result<Self, EnvelopeError> {
        let context = tombstone_context(record_id.clone())?;
        Ok(Self {
            record_id,
            deleted_at,
            audit_event_id,
            details: key.encrypt_field(&context, details)?,
        })
    }

    pub fn open(&self, key: &KeyLifecycle) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        key.decrypt_field(&tombstone_context(self.record_id.clone())?, &self.details)
    }

    #[must_use]
    pub const fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    #[must_use]
    pub const fn deleted_at(&self) -> TimestampMillis {
        self.deleted_at
    }

    #[must_use]
    pub const fn audit_event_id(&self) -> &AuditEventId {
        &self.audit_event_id
    }
}

impl fmt::Debug for EncryptedTombstone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedTombstone")
            .field("record_id", &self.record_id)
            .field("deleted_at", &self.deleted_at)
            .field("audit_event_id", &self.audit_event_id)
            .field("details", &"<encrypted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneWire {
    version: u8,
    record_id: RecordId,
    deleted_at: TimestampMillis,
    audit_event_id: AuditEventId,
    details: EncryptedFieldEnvelope,
}

impl Serialize for EncryptedTombstone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TombstoneWire {
            version: TOMBSTONE_VERSION,
            record_id: self.record_id.clone(),
            deleted_at: self.deleted_at,
            audit_event_id: self.audit_event_id.clone(),
            details: self.details.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedTombstone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TombstoneWire::deserialize(deserializer)?;
        if wire.version != TOMBSTONE_VERSION {
            return Err(de::Error::custom("unsupported encrypted tombstone version"));
        }
        Ok(Self {
            record_id: wire.record_id,
            deleted_at: wire.deleted_at,
            audit_event_id: wire.audit_event_id,
            details: wire.details,
        })
    }
}

fn tombstone_context(record_id: RecordId) -> Result<FieldContext, EnvelopeError> {
    Ok(FieldContext::new(
        record_id,
        FieldId::parse(TOMBSTONE_FIELD_ID)?,
        PrivacyClassification::default_for(PrivacyDomain::OrdinaryContact),
        FieldPurpose::Tombstone,
    ))
}
