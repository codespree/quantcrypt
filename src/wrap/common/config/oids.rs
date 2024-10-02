use crate::wrap::common::wrap_type::WrapType;

/// A trait to get the OID of a DSA
pub trait Oid {
    /// Get the OID for the DSA
    ///
    /// # Returns
    ///
    /// The OID for the DSA as a string
    fn get_oid(&self) -> String;
}

impl Oid for WrapType {
    /// Get the OID for the KDF
    ///
    /// # Returns
    ///
    /// The OID for the kdF
    fn get_oid(&self) -> String {
        match self {
            WrapType::Aes128 => "2.16.840.1.101.3.4.1.5",
            WrapType::Aes256 => "2.16.840.1.101.3.4.1.45",
        }
        .to_string()
    }
}
