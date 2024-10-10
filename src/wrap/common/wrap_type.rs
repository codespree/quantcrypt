use crate::wrap::common::config::oids::Oid;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// The type of a key wrap
#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum WrapType {
    /// AES 128
    Aes128,
    /// AES 192
    Aes256,
}

impl WrapType {
    /// Get all key wrap types
    ///
    /// # Returns
    ///
    /// A vector of all key wrap types
    pub fn all() -> Vec<WrapType> {
        WrapType::iter().collect()
    }

    /// Get the wrap type from an OID
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID to get the wrap type for
    ///
    /// # Returns
    ///
    /// The wrap type for the OID, or None if the OID is not found
    pub fn from_oid(oid: &str) -> Option<WrapType> {
        let all_wrap_types = WrapType::all();
        all_wrap_types
            .into_iter()
            .find(|wrap_type| wrap_type.get_oid() == oid)
    }
}
