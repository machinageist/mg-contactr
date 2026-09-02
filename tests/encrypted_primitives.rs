use mg_contacts::{
    audit::{
        ActorId, AuditAction, AuditError, AuditEventId, AuditTrail, NewAuditEvent, Provenance,
        RecordId, TimestampMillis,
    },
    envelope::{EnvelopeError, FieldContext, FieldId, FieldPurpose},
    keyring::KeyLifecycle,
    privacy::{
        AiApproval, Disclosure, ExportApproval, PrivacyClassification, PrivacyDomain, Sensitivity,
    },
    tombstone::EncryptedTombstone,
};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "correct horse battery staple";

fn unlocked_key() -> (tempfile::TempDir, KeyLifecycle) {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut key = KeyLifecycle::new(directory.path().join("key.json"));
    key.setup(PASSPHRASE, PASSPHRASE).unwrap();
    (directory, key)
}

#[test]
fn field_envelopes_round_trip_without_plaintext_and_never_reuse_a_nonce() {
    let (_directory, key) = unlocked_key();
    let context = FieldContext::new(
        RecordId::parse("person:01JTEST0000000000000000000").unwrap(),
        FieldId::parse("ordinary_contact.email.primary").unwrap(),
        PrivacyClassification::default_for(PrivacyDomain::OrdinaryContact),
        FieldPurpose::RecordField,
    );
    let plaintext = Zeroizing::new(b"private@example.test".to_vec());

    let first = key.encrypt_field(&context, &plaintext).unwrap();
    let second = key.encrypt_field(&context, &plaintext).unwrap();

    assert_ne!(first.nonce(), second.nonce());
    assert_ne!(first.ciphertext(), plaintext.as_slice());
    assert_eq!(
        key.decrypt_field(&context, &first).unwrap().as_slice(),
        plaintext.as_slice()
    );

    let json = serde_json::to_string(&first).unwrap();
    assert_eq!(json, serde_json::to_string(&first).unwrap());
    assert!(!json.contains("private@example.test"));
    assert!(!format!("{first:?}").contains("private@example.test"));
}

#[test]
fn authentication_binds_every_domain_separating_context_component() {
    let (_directory, key) = unlocked_key();
    let base = FieldContext::new(
        RecordId::parse("person:01JTEST0000000000000000000").unwrap(),
        FieldId::parse("esoteric.notes.private").unwrap(),
        PrivacyClassification::default_for(PrivacyDomain::Esoteric),
        FieldPurpose::RecordField,
    );
    let envelope = key
        .encrypt_field(&base, &Zeroizing::new(b"secret ritual note".to_vec()))
        .unwrap();

    let altered_contexts = [
        FieldContext::new(
            RecordId::parse("person:01JTEST0000000000000000001").unwrap(),
            base.field_id().clone(),
            base.privacy(),
            base.purpose(),
        ),
        FieldContext::new(
            base.record_id().clone(),
            FieldId::parse("esoteric.notes.other").unwrap(),
            base.privacy(),
            base.purpose(),
        ),
        FieldContext::new(
            base.record_id().clone(),
            base.field_id().clone(),
            PrivacyClassification::default_for(PrivacyDomain::BirthChart),
            base.purpose(),
        ),
        FieldContext::new(
            base.record_id().clone(),
            base.field_id().clone(),
            base.privacy(),
            FieldPurpose::Tombstone,
        ),
    ];

    for altered in altered_contexts {
        assert_eq!(
            key.decrypt_field(&altered, &envelope).unwrap_err(),
            EnvelopeError::AuthenticationFailed
        );
    }
}

#[test]
fn envelope_nonce_ciphertext_and_tag_tampering_fail_authentication() {
    let (_directory, key) = unlocked_key();
    let context = FieldContext::new(
        RecordId::parse("person:01JTEST0000000000000000000").unwrap(),
        FieldId::parse("birth_chart.location").unwrap(),
        PrivacyClassification::default_for(PrivacyDomain::BirthChart),
        FieldPurpose::RecordField,
    );
    let envelope = key
        .encrypt_field(&context, &Zeroizing::new(b"private coordinates".to_vec()))
        .unwrap();

    for field in ["nonce", "ciphertext", "tag"] {
        let mut value = serde_json::to_value(&envelope).unwrap();
        let bytes = value[field].as_array_mut().unwrap();
        bytes[0] = serde_json::json!(bytes[0].as_u64().unwrap() ^ 1);
        let tampered = serde_json::from_value(value).unwrap();
        assert_eq!(
            key.decrypt_field(&context, &tampered).unwrap_err(),
            EnvelopeError::AuthenticationFailed
        );
    }
}

#[test]
fn locked_keys_and_malformed_envelopes_fail_with_redacted_deterministic_errors() {
    let (_directory, mut key) = unlocked_key();
    let context = FieldContext::new(
        RecordId::parse("person:01JTEST0000000000000000000").unwrap(),
        FieldId::parse("relationship.private_note").unwrap(),
        PrivacyClassification::default_for(PrivacyDomain::Relationship),
        FieldPurpose::RecordField,
    );
    let envelope = key
        .encrypt_field(&context, &Zeroizing::new(b"never log this".to_vec()))
        .unwrap();
    let mut value = serde_json::to_value(&envelope).unwrap();
    value["version"] = serde_json::json!(99);
    let error =
        serde_json::from_value::<mg_contacts::envelope::EncryptedFieldEnvelope>(value).unwrap_err();
    assert!(!error.to_string().contains("never log this"));

    key.lock();
    assert_eq!(
        key.decrypt_field(&context, &envelope).unwrap_err(),
        EnvelopeError::KeyLocked
    );
    assert_eq!(
        EnvelopeError::KeyLocked.to_string(),
        "encryption key is locked"
    );
}

#[test]
fn disclosure_is_default_deny_and_requires_separate_explicit_approvals() {
    for domain in [
        PrivacyDomain::OrdinaryContact,
        PrivacyDomain::Relationship,
        PrivacyDomain::BirthChart,
        PrivacyDomain::Esoteric,
    ] {
        let classification = PrivacyClassification::default_for(domain);
        assert_eq!(classification.export(), Disclosure::Denied);
        assert_eq!(classification.ai(), Disclosure::Denied);
        assert_eq!(classification.sensitivity(), Sensitivity::Sensitive);

        let export_only = classification.approve_export(&ExportApproval::explicit());
        assert_eq!(export_only.export(), Disclosure::Approved);
        assert_eq!(export_only.ai(), Disclosure::Denied);

        let ai_only = classification.approve_ai(&AiApproval::explicit());
        assert_eq!(ai_only.export(), Disclosure::Denied);
        assert_eq!(ai_only.ai(), Disclosure::Approved);
    }
}

#[test]
fn audit_trail_is_append_only_ordered_and_contains_no_sensitive_payload_slot() {
    let subject = RecordId::parse("person:01JTEST0000000000000000000").unwrap();
    let actor = ActorId::parse("operator:local").unwrap();
    let provenance = Provenance::new("manual", "local-entry").unwrap();
    let mut trail = AuditTrail::new(subject.clone());

    trail
        .append(NewAuditEvent::new(
            AuditEventId::parse("audit:01JTEST0000000000000000000").unwrap(),
            TimestampMillis::new(1_725_000_000_000),
            actor.clone(),
            AuditAction::Created,
            provenance.clone(),
        ))
        .unwrap();
    trail
        .append(NewAuditEvent::new(
            AuditEventId::parse("audit:01JTEST0000000000000000001").unwrap(),
            TimestampMillis::new(1_725_000_000_001),
            actor,
            AuditAction::SoftDeleted,
            provenance,
        ))
        .unwrap();

    assert_eq!(trail.entries()[0].sequence(), 1);
    assert_eq!(trail.entries()[1].sequence(), 2);
    assert_eq!(
        trail.entries()[1].previous_event_id(),
        Some(trail.entries()[0].event_id())
    );
    let json = serde_json::to_string(&trail).unwrap();
    assert_eq!(json, serde_json::to_string(&trail).unwrap());
    assert!(!json.contains("payload"));

    let error = trail
        .append(NewAuditEvent::new(
            AuditEventId::parse("audit:01JTEST0000000000000000002").unwrap(),
            TimestampMillis::new(1_724_999_999_999),
            ActorId::parse("operator:local").unwrap(),
            AuditAction::Updated,
            Provenance::new("manual", "local-entry").unwrap(),
        ))
        .unwrap_err();
    assert_eq!(error, AuditError::TimestampRegression);
    assert_eq!(trail.entries().len(), 2);

    let mut value = serde_json::to_value(&trail).unwrap();
    value["entries"][1]["previous_event_id"] =
        serde_json::json!("audit:01JTEST0000000000000000999");
    assert!(serde_json::from_value::<AuditTrail>(value).is_err());
}

#[test]
fn tombstone_metadata_is_stable_while_delete_details_remain_encrypted() {
    let (_directory, key) = unlocked_key();
    let record_id = RecordId::parse("person:01JTEST0000000000000000000").unwrap();
    let event_id = AuditEventId::parse("audit:01JTEST0000000000000000001").unwrap();
    let details = Zeroizing::new(b"requested by third party; private reason".to_vec());

    let tombstone = EncryptedTombstone::seal(
        &key,
        record_id.clone(),
        TimestampMillis::new(1_725_000_000_001),
        event_id.clone(),
        &details,
    )
    .unwrap();

    assert_eq!(tombstone.record_id(), &record_id);
    assert_eq!(tombstone.audit_event_id(), &event_id);
    assert_eq!(tombstone.open(&key).unwrap().as_slice(), details.as_slice());
    let json = serde_json::to_string(&tombstone).unwrap();
    assert_eq!(json, serde_json::to_string(&tombstone).unwrap());
    assert!(!json.contains("requested by third party"));
    assert!(!format!("{tombstone:?}").contains("private reason"));

    let mut altered = serde_json::to_value(&tombstone).unwrap();
    altered["record_id"] = serde_json::json!("person:01JTEST0000000000000000009");
    let altered = serde_json::from_value::<EncryptedTombstone>(altered).unwrap();
    assert_eq!(
        altered.open(&key).unwrap_err(),
        EnvelopeError::AuthenticationFailed
    );
}
