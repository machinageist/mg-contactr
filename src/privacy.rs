//! Typed privacy policy primitives.
//!
//! These types establish the fail-closed prerequisite for encrypted envelopes
//! and persistence. They intentionally define no wire format, durable identity,
//! database schema, encryption envelope, or migration authority.

/// The independently classified field groups required by the product contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivacyDomain {
    /// Names, contact methods, addresses, and other ordinary contact data.
    OrdinaryContact,
    /// Relationship edges, roles, households, and related metadata.
    Relationship,
    /// Birth events, chart inputs, and derived astrological records.
    BirthChart,
    /// Thelemic, Hermetic, and other user-supplied esoteric records.
    Esoteric,
}

/// Whether plaintext may be considered for an explicitly approved index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    /// The value must remain outside plaintext indexes.
    Sensitive,
    /// The value may be indexed only with a separate explicit approval.
    NonSensitive,
}

/// A field-group privacy classification with fail-closed defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrivacyClassification {
    domain: PrivacyDomain,
    sensitivity: Sensitivity,
}

impl PrivacyClassification {
    /// Classify a field group using the required sensitive default.
    #[must_use]
    pub const fn default_for(domain: PrivacyDomain) -> Self {
        Self {
            domain,
            sensitivity: Sensitivity::Sensitive,
        }
    }

    /// Explicitly classify a field group as non-sensitive.
    ///
    /// This classification alone does not authorize indexing. Callers must
    /// also supply a [`NonSensitiveIndexApproval`].
    #[must_use]
    pub const fn non_sensitive(domain: PrivacyDomain) -> Self {
        Self {
            domain,
            sensitivity: Sensitivity::NonSensitive,
        }
    }

    /// Return the independently classified privacy domain.
    #[must_use]
    pub const fn domain(self) -> PrivacyDomain {
        self.domain
    }

    /// Return the sensitivity classification.
    #[must_use]
    pub const fn sensitivity(self) -> Sensitivity {
        self.sensitivity
    }

    /// Decide whether plaintext is eligible for an approved non-sensitive index.
    ///
    /// This fails closed unless the data is explicitly classified as
    /// non-sensitive and an explicit approval token is present.
    #[must_use]
    pub const fn is_eligible_for_index(self, approval: Option<&NonSensitiveIndexApproval>) -> bool {
        matches!(self.sensitivity, Sensitivity::NonSensitive) && approval.is_some()
    }
}

/// Marker that a caller explicitly selected a non-sensitive index operation.
///
/// The token carries no record or field identity because those contracts are
/// intentionally deferred to the domain and persistence slices. It is not a
/// substitute for the durable, field-scoped operator approval required by
/// those later boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonSensitiveIndexApproval {
    _private: (),
}

impl NonSensitiveIndexApproval {
    /// Record an explicit approval for the current operation.
    #[must_use]
    pub const fn explicit() -> Self {
        Self { _private: () }
    }
}
