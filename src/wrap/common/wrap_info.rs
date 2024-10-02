use crate::wrap::common::config::oids::Oid;
use crate::wrap::common::wrap_type::WrapType;

/// A structure to represent metadata about a KDF
#[derive(Clone)]
pub struct WrapInfo {
    /// The type of KDF
    pub wrap_type: WrapType,
    /// The OID of the KDF
    pub oid: String,
}

impl WrapInfo {
    /// Create a new Wrap metadata structure
    ///
    /// # Arguments
    ///
    /// * `wrap_type` - The type of wrap
    ///
    /// # Returns
    ///
    /// A new wrap metadata structure
    pub fn new(wrap_type: WrapType) -> Self {
        let oid = wrap_type.get_oid();
        WrapInfo { wrap_type, oid }
    }
}
