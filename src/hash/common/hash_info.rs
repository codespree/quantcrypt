use crate::hash::common::config::oids::Oid;
use crate::hash::common::hash_type::HashType;

/// A structure to represent metadata about a KDF
#[derive(Clone)]
#[allow(dead_code)]
pub struct HashInfo {
    /// The type of Hash
    pub hash_type: HashType,
    /// The OID of the Hash
    pub oid: String,
}

impl HashInfo {
    /// Create a new hash metadata structure
    ///
    /// # Arguments
    ///
    /// * `hash_type` - The type of Hash
    ///
    /// # Returns
    ///
    /// A new hash metadata structure
    pub fn new(hash_type: HashType) -> Self {
        let oid = hash_type.get_oid();
        HashInfo { hash_type, oid }
    }
}
