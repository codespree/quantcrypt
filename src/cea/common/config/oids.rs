use crate::cea::common::cea_type::CeaType;

/// A trait to get the OID of a CAE
pub trait Oid {
    /// Get the OID for the CAE
    ///
    /// # Returns
    ///
    /// The OID for the CAE as a string
    fn get_oid(&self) -> String;
}

impl Oid for CeaType {
    /// Get the OID for the CAE
    ///
    /// # Returns
    ///
    /// The OID for the CAE
    fn get_oid(&self) -> String {
        match self {
            CeaType::Aes128Gcm => "2.16.840.1.101.3.4.1.6",
            CeaType::Aes192Gcm => "2.16.840.1.101.3.4.1.26",
            CeaType::Aes256Gcm => "2.16.840.1.101.3.4.1.46",
            //TODO: Enable CBC
            //CeaType::Aes128Cbc => "2.16.840.1.101.3.4.1.7",
            //CeaType::Aes192Cbc => "2.16.840.1.101.3.4.1.27",
            //CeaType::Aes256Cbc => "2.16.840.1.101.3.4.1.47",
        }
        .to_string()
    }
}
