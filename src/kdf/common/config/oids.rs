use crate::kdf::common::kdf_type::KdfType;

/// A trait to get the OID of a DSA
pub trait Oid {
    /// Get the OID for the DSA
    ///
    /// # Returns
    ///
    /// The OID for the DSA as a string
    fn get_oid(&self) -> String;
}

impl Oid for KdfType {
    /// Get the OID for the KDF
    ///
    /// # Returns
    ///
    /// The OID for the kdF
    fn get_oid(&self) -> String {
        match self {
            KdfType::HkdfWithSha256 => "1.2.840.113549.1.9.16.3.28",
            KdfType::HkdfWithSha384 => "1.2.840.113549.1.9.16.3.29",
            KdfType::HkdfWithSha512 => "1.2.840.113549.1.9.16.3.30",
            KdfType::Kmac128 => "2.16.840.1.101.3.4.2.21",
            KdfType::Kmac256 => "2.16.840.1.101.3.4.2.22",
            KdfType::Sha3_256 => "2.16.840.1.101.3.4.2.8",
            KdfType::Sha3_512 => "2.16.840.1.101.3.4.2.10",
            KdfType::Sha3_384 => "2.16.840.1.101.3.4.2.9",
        }
        .to_string()
    }
}
