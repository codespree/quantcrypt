#![doc = include_str!("../README.md")]

mod aead;
mod asn1;
mod cea;
mod cms;
mod dsa;
mod errors;
mod hash;
mod kdf;
mod kem;
mod utils;
mod wrap;

pub use errors::QuantCryptError;

/// Dealing with pure/composite certificates
pub mod certificates {
    pub use crate::asn1::cert_builder::CertValidity;
    pub use crate::asn1::cert_builder::CertificateBuilder;
    pub use crate::asn1::cert_builder::Profile;
    pub use crate::asn1::certificate::Certificate;
}

/// Dealing with pure/composite keys
pub mod keys {
    pub use crate::asn1::private_key::PrivateKey;
    pub use crate::asn1::public_key::PublicKey;
}

/// Defines DSA types and key generation
pub mod dsas {
    pub use crate::dsa::api::algorithm::DsaAlgorithm;
    pub use crate::dsa::api::key_generator::DsaKeyGenerator;
}

/// Defines KEM types and key generation
pub mod kems {
    pub use crate::kem::api::algorithm::KemAlgorithm;
    pub use crate::kem::api::key_generator::KemKeyGenerator;
}

/// Defines the types of key derivation functions
pub mod kdfs {
    pub use crate::kdf::api::KdfType;
}

/// Defines the types of key wrapping functions
pub mod wraps {
    pub use crate::wrap::api::WrapType;
}

/// Dealing with Cryptographic Message Syntax (CMS)
pub mod content {
    pub use crate::cms::api::Attribute;
    pub use crate::cms::api::AttributeType;
    pub use crate::cms::api::AttributeValue;
    pub use crate::cms::api::AuthEnvelopedDataContent;
    pub use crate::cms::api::CertificateStore;
    pub use crate::cms::api::CmsVersion;
    pub use crate::cms::api::ContentEncryptionAlgorithm;
    pub use crate::cms::api::ContentEncryptionAlgorithmAead;
    pub use crate::cms::api::DirectoryCertificateStore;
    pub use crate::cms::api::EnvelopedDataContent;
    pub use crate::cms::api::KdfType;
    pub use crate::cms::api::ObjectIdentifier;
    pub use crate::cms::api::SetOfVec;
    pub use crate::cms::api::Tag;
    pub use crate::cms::api::Tagged;
    pub use crate::cms::api::UserKeyingMaterial;
    pub use crate::cms::api::WrapType;
}
