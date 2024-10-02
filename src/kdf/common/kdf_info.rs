use crate::kdf::common::config::oids::Oid;
use crate::kdf::common::kdf_type::KdfType;

/// A structure to represent metadata about a KDF
#[derive(Clone)]
pub struct KdfInfo {
    /// The type of KDF
    pub kdf_type: KdfType,
    /// The OID of the KDF
    pub oid: String,
}

impl KdfInfo {
    /// Create a new KDF metadata structure
    ///
    /// # Arguments
    ///
    /// * `kdf_type` - The type of DSA
    ///
    /// # Returns
    ///
    /// A new KDF metadata structure
    pub fn new(kdf_type: KdfType) -> Self {
        let oid = kdf_type.get_oid();
        KdfInfo { kdf_type, oid }
    }
}
