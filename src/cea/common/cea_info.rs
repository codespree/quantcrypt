use crate::cea::common::cea_type::CeaType;
use crate::cea::common::config::oids::Oid;

/// A structure to represent metadata about a KDF
#[derive(Clone)]
pub struct CeaInfo {
    /// The type of KDF
    pub cea_type: CeaType,
    /// The OID of the KDF
    pub oid: String,
    /// Does it support AAD
    pub is_aad_supported: bool,
}

impl CeaInfo {
    /// Create a new CEA metadata structure
    ///
    /// # Arguments
    ///
    /// * `cea_type` - The type of CEA
    ///
    /// # Returns
    ///
    /// A new CEA metadata structure
    pub fn new(cea_type: CeaType) -> Self {
        let oid = cea_type.get_oid();
        let is_aad_supported = matches!(
            cea_type,
            CeaType::Aes128Gcm | CeaType::Aes192Gcm | CeaType::Aes256Gcm
        );

        CeaInfo {
            cea_type,
            oid,
            is_aad_supported,
        }
    }
}
