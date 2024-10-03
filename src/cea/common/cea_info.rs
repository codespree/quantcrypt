use crate::cea::common::cea_type::CeaType;
use crate::cea::common::config::oids::Oid;

/// A structure to represent metadata about a KDF
#[derive(Clone)]
pub struct CeaInfo {
    /// The type of KDF
    pub cea_type: CeaType,
    /// The OID of the KDF
    pub oid: String,
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
        CeaInfo { cea_type, oid }
    }
}
