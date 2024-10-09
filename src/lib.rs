#![doc = include_str!("../README.md")]

mod asn1;
mod cea;
mod cms;
mod dsa;
mod errors;
mod kdf;
mod kem;
mod oid_mapper;
mod utils;
mod wrap;

pub use errors::QuantCryptError;

// Dealing with certificates
pub use crate::asn1::cert_builder::CertValidity;
pub use crate::asn1::cert_builder::CertificateBuilder;
pub use crate::asn1::cert_builder::Profile;
pub use crate::asn1::certificate::Certificate;
pub use crate::asn1::private_key::PrivateKey;
pub use crate::asn1::public_key::PublicKey;

// DSA APIs
pub use crate::dsa::api::algorithm::DsaAlgorithm;
pub use crate::dsa::api::key_generator::DsaKeyGenerator;

// KEM APIs
pub use crate::kem::api::algorithm::KemAlgorithm;
pub use crate::kem::api::key_generator::KemKeyGenerator;

// CMS
pub use cms::api::Attribute;
pub use cms::api::AttributeType;
pub use cms::api::AttributeValue;
pub use cms::api::AuthEnvelopedDataContent;
pub use cms::api::CertificateStore;
pub use cms::api::CmsVersion;
pub use cms::api::ContentEncryptionAlgorithm;
pub use cms::api::ContentEncryptionAlgorithmAead;
pub use cms::api::DirectoryCertificateStore;
pub use cms::api::DummyCertificateStore;
pub use cms::api::EnvelopedDataContent;
pub use cms::api::KdfType;
pub use cms::api::ObjectIdentifier;
pub use cms::api::SetOfVec;
pub use cms::api::Tag;
pub use cms::api::Tagged;
pub use cms::api::UserKeyingMaterial;
pub use cms::api::WrapType;
