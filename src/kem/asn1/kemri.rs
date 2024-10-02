//! `KEMRecipientInfo`-related types

// Thanks to Carl Wallace for this code:
// https://github.com/carl-wallace/kemri_toy/blob/main/src/asn1/kemri.rs

use cms::{
    content_info::CmsVersion,
    enveloped_data::{EncryptedKey, RecipientIdentifier, UserKeyingMaterial},
};
use der::{asn1::OctetString, Sequence};
use spki::AlgorithmIdentifierOwned;

/// The `KEMRecipientInfo` type is defined in [draft-ietf-lamps-cms-kemri-07 Section 3]
/// ```text
///   KEMRecipientInfo ::= SEQUENCE {
///     version CMSVersion,  -- always set to 0
///     rid RecipientIdentifier,
///     kem KEMAlgorithmIdentifier,
///     kemct OCTET STRING,
///     kdf KeyDerivationAlgorithmIdentifier,
///     kekLength INTEGER (1..65535),
///     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
///     wrap KeyEncryptionAlgorithmIdentifier,
///     encryptedKey EncryptedKey }
/// ```
/// [draft-ietf-lamps-cms-kemri-07 Section 3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-07#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KemRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub kem: AlgorithmIdentifierOwned,
    pub kem_ct: OctetString,
    pub kdf: AlgorithmIdentifierOwned,
    pub kek_length: u16,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub ukm: Option<UserKeyingMaterial>,
    pub wrap: AlgorithmIdentifierOwned,
    pub encrypted_key: EncryptedKey,
}

/// The `CMSORIforKEMOtherInfo` type is defined in [draft-ietf-lamps-cms-kemri-07 Section 5]
/// ```text
///       CMSORIforKEMOtherInfo ::= SEQUENCE {
///         wrap KeyEncryptionAlgorithmIdentifier,
///         kekLength INTEGER (1..65535),
///         ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }
/// ```
/// [draft-ietf-lamps-cms-kemri-07 Section 5]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-07#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CmsOriForKemOtherInfo {
    pub wrap: AlgorithmIdentifierOwned,
    pub kek_length: u16,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub ukm: Option<UserKeyingMaterial>,
}
