use mg_contacts::privacy::{
    NonSensitiveIndexApproval, PrivacyClassification, PrivacyDomain, Sensitivity,
};

#[test]
fn every_domain_defaults_to_sensitive_and_unindexable() {
    let approval = NonSensitiveIndexApproval::explicit();
    for domain in [
        PrivacyDomain::OrdinaryContact,
        PrivacyDomain::Relationship,
        PrivacyDomain::BirthChart,
        PrivacyDomain::Esoteric,
    ] {
        let classification = PrivacyClassification::default_for(domain);
        assert_eq!(classification.domain(), domain);
        assert_eq!(classification.sensitivity(), Sensitivity::Sensitive);
        assert!(!classification.is_eligible_for_index(None));
        assert!(!classification.is_eligible_for_index(Some(&approval)));
    }
}

#[test]
fn indexing_requires_both_non_sensitive_classification_and_explicit_approval() {
    let sensitive = PrivacyClassification::default_for(PrivacyDomain::OrdinaryContact);
    let non_sensitive = PrivacyClassification::non_sensitive(PrivacyDomain::OrdinaryContact);
    let approval = NonSensitiveIndexApproval::explicit();

    assert!(!sensitive.is_eligible_for_index(Some(&approval)));
    assert!(!non_sensitive.is_eligible_for_index(None));
    assert!(non_sensitive.is_eligible_for_index(Some(&approval)));
}

#[test]
fn privacy_domains_remain_typed_and_independent() {
    let ordinary = PrivacyClassification::non_sensitive(PrivacyDomain::OrdinaryContact);
    let relationship = PrivacyClassification::default_for(PrivacyDomain::Relationship);
    let birth_chart = PrivacyClassification::default_for(PrivacyDomain::BirthChart);
    let esoteric = PrivacyClassification::default_for(PrivacyDomain::Esoteric);

    assert_eq!(ordinary.sensitivity(), Sensitivity::NonSensitive);
    for classification in [relationship, birth_chart, esoteric] {
        assert_eq!(classification.sensitivity(), Sensitivity::Sensitive);
    }
}

#[test]
fn debug_output_contains_policy_only_and_no_field_values() {
    let classification = PrivacyClassification::default_for(PrivacyDomain::Esoteric);
    let debug = format!("{classification:?}");

    assert_eq!(
        debug,
        "PrivacyClassification { domain: Esoteric, sensitivity: Sensitive }"
    );
}
