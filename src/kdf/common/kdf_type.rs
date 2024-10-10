use crate::kdf::common::config::oids::Oid;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// Define the KDF types
#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum KdfType {
    /// Hkdf with SHA-256
    HkdfWithSha256,
    /// Hkdf with SHA-512
    HkdfWithSha512,
    /// Kmac with 128-bit key
    Kmac128,
    /// Kmac with 256-bit key
    Kmac256,
}

impl KdfType {
    /// Get all KDF types
    pub fn all() -> Vec<KdfType> {
        KdfType::iter().collect()
    }

    /// Get the OID of the KDF
    pub fn from_oid(oid: &str) -> Option<KdfType> {
        let all_kdf_types = KdfType::all();
        all_kdf_types
            .into_iter()
            .find(|kdf_type| kdf_type.get_oid() == oid)
    }
}
