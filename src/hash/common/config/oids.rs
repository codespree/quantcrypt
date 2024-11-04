use crate::hash::common::hash_type::HashType;

/// A trait to get the OID of a Hash
pub trait Oid {
    /// Get the OID for the Hash
    ///
    /// # Returns
    ///
    /// The OID for the Hash as a string
    fn get_oid(&self) -> String;
}

impl Oid for HashType {
    /// Get the OID for the Hash
    ///
    /// # Returns
    ///
    /// The OID for the Hash
    fn get_oid(&self) -> String {
        match self {
            HashType::Sha256 => "2.16.840.1.101.3.4.2.1",
            HashType::Sha512 => "2.16.840.1.101.3.4.2.3",
            HashType::Shake128 => "2.16.840.1.101.3.4.2.11",
            HashType::Shake256 => "2.16.840.1.101.3.4.2.12",
        }
        .to_string()
    }
}
