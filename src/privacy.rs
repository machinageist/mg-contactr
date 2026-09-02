//! Typed, fail-closed privacy policy primitives.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

const PRIVACY_CLASSIFICATION_VERSION: u8 = 1;

/// The independently classified field groups required by the product contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// The value must remain outside plaintext indexes.
    Sensitive,
    /// The value may be indexed only with a separate explicit approval.
    NonSensitive,
}

/// Whether one narrowly scoped disclosure has been explicitly approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    /// Disclosure is forbidden.
    Denied,
    /// Disclosure was explicitly approved for this field group.
    Approved,
}

/// A versioned field-group privacy classification with fail-closed defaults.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrivacyClassification {
    domain: PrivacyDomain,
    sensitivity: Sensitivity,
    export: Disclosure,
    ai: Disclosure,
}

impl PrivacyClassification {
    /// Classify a field group using sensitive and non-disclosable defaults.
    #[must_use]
    pub const fn default_for(domain: PrivacyDomain) -> Self {
        Self {
            domain,
            sensitivity: Sensitivity::Sensitive,
            export: Disclosure::Denied,
            ai: Disclosure::Denied,
        }
    }

    /// Explicitly classify a field group as non-sensitive.
    ///
    /// This classification alone does not authorize indexing, export, or AI use.
    #[must_use]
    pub const fn non_sensitive(domain: PrivacyDomain) -> Self {
        Self {
            domain,
            sensitivity: Sensitivity::NonSensitive,
            export: Disclosure::Denied,
            ai: Disclosure::Denied,
        }
    }

    /// Return a copy with field-group export explicitly approved.
    #[must_use]
    pub const fn approve_export(mut self, _approval: &ExportApproval) -> Self {
        self.export = Disclosure::Approved;
        self
    }

    /// Return a copy with field-group AI use explicitly approved.
    #[must_use]
    pub const fn approve_ai(mut self, _approval: &AiApproval) -> Self {
        self.ai = Disclosure::Approved;
        self
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

    /// Return the export disclosure decision.
    #[must_use]
    pub const fn export(self) -> Disclosure {
        self.export
    }

    /// Return the AI disclosure decision.
    #[must_use]
    pub const fn ai(self) -> Disclosure {
        self.ai
    }

    /// Decide whether plaintext is eligible for an approved non-sensitive index.
    #[must_use]
    pub const fn is_eligible_for_index(self, approval: Option<&NonSensitiveIndexApproval>) -> bool {
        matches!(self.sensitivity, Sensitivity::NonSensitive) && approval.is_some()
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for PrivacyClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyClassification")
            .field("domain", &self.domain)
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyClassificationWire {
    version: u8,
    domain: PrivacyDomain,
    sensitivity: Sensitivity,
    export: Disclosure,
    ai: Disclosure,
}

impl Serialize for PrivacyClassification {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PrivacyClassificationWire {
            version: PRIVACY_CLASSIFICATION_VERSION,
            domain: self.domain,
            sensitivity: self.sensitivity,
            export: self.export,
            ai: self.ai,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PrivacyClassification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PrivacyClassificationWire::deserialize(deserializer)?;
        if wire.version != PRIVACY_CLASSIFICATION_VERSION {
            return Err(de::Error::custom(
                "unsupported privacy classification version",
            ));
        }
        Ok(Self {
            domain: wire.domain,
            sensitivity: wire.sensitivity,
            export: wire.export,
            ai: wire.ai,
        })
    }
}

macro_rules! approval_token {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            _private: (),
        }

        impl $name {
            /// Record an explicit approval for the current operation.
            #[must_use]
            pub const fn explicit() -> Self {
                Self { _private: () }
            }
        }
    };
}

approval_token!(
    NonSensitiveIndexApproval,
    "Marker that a caller explicitly selected a non-sensitive index operation."
);
approval_token!(
    ExportApproval,
    "Marker that export was explicitly approved for this field group."
);
approval_token!(
    AiApproval,
    "Marker that AI use was explicitly approved for this field group."
);
