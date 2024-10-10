use crate::cea::common::config::oids::Oid;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
#[allow(clippy::enum_variant_names)]
/// The type of CEA
pub enum CeaType {
    /// AES 128 GCM
    Aes128Gcm,
    /// AES 192 GCM
    Aes192Gcm,
    /// AES 256 GCM
    Aes256Gcm,
    /// AES 128 CBC with padding
    Aes128CbcPad,
    /// AES 192 CBC with padding
    Aes192CbcPad,
    /// AES 256 CBC with padding
    Aes256CbcPad,
}

impl CeaType {
    /// Get all CEA types
    pub fn all() -> Vec<CeaType> {
        CeaType::iter().collect()
    }

    /// Get the CeaType from an OID
    pub fn from_oid(oid: &str) -> Option<CeaType> {
        let all_cea_types = CeaType::all();
        all_cea_types
            .into_iter()
            .find(|cea_type| cea_type.get_oid() == oid)
    }
}
