//! Validated append-only audit and provenance primitives.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

const MAX_ID_BYTES: usize = 256;
const MAX_PROVENANCE_BYTES: usize = 1024;
const MAX_AUDIT_EVENTS: usize = 100_000;
const AUDIT_TRAIL_VERSION: u8 = 1;

macro_rules! validated_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AuditError> {
                let value = value.into();
                validate_token(&value, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

validated_id!(RecordId, "record id");
validated_id!(ActorId, "actor id");
validated_id!(AuditEventId, "audit event id");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimestampMillis(i64);

impl TimestampMillis {
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Created,
    Updated,
    SoftDeleted,
    Restored,
    PrivacyChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    source: String,
    reference: String,
}

impl Provenance {
    pub fn new(
        source: impl Into<String>,
        reference: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let source = source.into();
        let reference = reference.into();
        validate_token(&source, "provenance source")?;
        validate_text(&reference, "provenance reference", MAX_PROVENANCE_BYTES)?;
        Ok(Self { source, reference })
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    event_id: AuditEventId,
    timestamp: TimestampMillis,
    actor: ActorId,
    action: AuditAction,
    provenance: Provenance,
}

impl NewAuditEvent {
    #[must_use]
    pub const fn new(
        event_id: AuditEventId,
        timestamp: TimestampMillis,
        actor: ActorId,
        action: AuditAction,
        provenance: Provenance,
    ) -> Self {
        Self {
            event_id,
            timestamp,
            actor,
            action,
            provenance,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    sequence: u64,
    event_id: AuditEventId,
    previous_event_id: Option<AuditEventId>,
    timestamp: TimestampMillis,
    actor: ActorId,
    action: AuditAction,
    provenance: Provenance,
}

impl AuditEvent {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn event_id(&self) -> &AuditEventId {
        &self.event_id
    }

    #[must_use]
    pub const fn previous_event_id(&self) -> Option<&AuditEventId> {
        self.previous_event_id.as_ref()
    }

    #[must_use]
    pub const fn timestamp(&self) -> TimestampMillis {
        self.timestamp
    }

    // What the event records; every other field could already be read
    #[must_use]
    pub const fn action(&self) -> AuditAction {
        self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrail {
    subject: RecordId,
    entries: Vec<AuditEvent>,
}

impl AuditTrail {
    #[must_use]
    pub const fn new(subject: RecordId) -> Self {
        Self {
            subject,
            entries: Vec::new(),
        }
    }

    pub fn append(&mut self, event: NewAuditEvent) -> Result<&AuditEvent, AuditError> {
        if self.entries.len() >= MAX_AUDIT_EVENTS {
            return Err(AuditError::SequenceOverflow);
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.event_id == event.event_id)
        {
            return Err(AuditError::DuplicateEvent);
        }
        if self
            .entries
            .last()
            .is_some_and(|last| event.timestamp <= last.timestamp)
        {
            return Err(AuditError::TimestampRegression);
        }
        let sequence = u64::try_from(self.entries.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(AuditError::SequenceOverflow)?;
        let previous_event_id = self.entries.last().map(|entry| entry.event_id.clone());
        self.entries.push(AuditEvent {
            sequence,
            event_id: event.event_id,
            previous_event_id,
            timestamp: event.timestamp,
            actor: event.actor,
            action: event.action,
            provenance: event.provenance,
        });
        self.entries.last().ok_or(AuditError::SequenceOverflow)
    }

    #[must_use]
    pub fn subject(&self) -> &RecordId {
        &self.subject
    }

    #[must_use]
    pub fn entries(&self) -> &[AuditEvent] {
        &self.entries
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditTrailWire {
    version: u8,
    subject: RecordId,
    entries: Vec<AuditEvent>,
}

impl Serialize for AuditTrail {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        AuditTrailWire {
            version: AUDIT_TRAIL_VERSION,
            subject: self.subject.clone(),
            entries: self.entries.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuditTrail {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuditTrailWire::deserialize(deserializer)?;
        if wire.version != AUDIT_TRAIL_VERSION {
            return Err(de::Error::custom("unsupported audit trail version"));
        }
        if wire.entries.len() > MAX_AUDIT_EVENTS {
            return Err(de::Error::custom("audit trail exceeds the entry limit"));
        }
        let mut rebuilt = Self::new(wire.subject);
        for entry in wire.entries {
            if entry.sequence != rebuilt.entries.len() as u64 + 1
                || entry.previous_event_id.as_ref()
                    != rebuilt.entries.last().map(|item| &item.event_id)
            {
                return Err(de::Error::custom("invalid audit chain"));
            }
            rebuilt
                .append(NewAuditEvent::new(
                    entry.event_id,
                    entry.timestamp,
                    entry.actor,
                    entry.action,
                    entry.provenance,
                ))
                .map_err(de::Error::custom)?;
        }
        Ok(rebuilt)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit identifier is invalid")]
    InvalidIdentifier,
    #[error("audit provenance is invalid")]
    InvalidProvenance,
    #[error("audit timestamp must increase")]
    TimestampRegression,
    #[error("audit event already exists")]
    DuplicateEvent,
    #[error("audit sequence is exhausted")]
    SequenceOverflow,
}

fn validate_token(value: &str, _field: &'static str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(AuditError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, _field: &'static str, max: usize) -> Result<(), AuditError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(AuditError::InvalidProvenance)
    } else {
        Ok(())
    }
}
