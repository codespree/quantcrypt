use crate::{kdf::common::kdf_type::KdfType, QuantCryptError};

use crate::kdf::common::config::oids::Oid;
use crate::kdf::common::kdf_info::KdfInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Kdf {
    /// Create a new Kdf instance
    ///
    /// # Arguments
    ///
    /// * `kdf_type` - The type of KDF to create
    fn new(kdf_type: KdfType) -> Result<Self>
    where
        Self: Sized;

    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_kdf_types = KdfType::all();
        for kdf_type in all_kdf_types {
            if kdf_type.get_oid() == oid {
                let kdf = Self::new(kdf_type)?;
                return Ok(kdf);
            }
        }
        Err(QuantCryptError::InvalidOid)
    }

    /// Get KDF metadata information such as OID
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the KDF
    fn get_kdf_info(&self) -> KdfInfo;

    /// Derive a key
    ///
    /// # Arguments
    ///
    /// * `ikm` - The input keying material
    /// * `info` - The context and application specific information
    /// * `length` - The length of the derived key
    /// * `salt` - Optional salt
    ///
    /// # Returns
    ///
    /// The derived key
    fn derive(
        &self,
        ikm: &[u8],
        info: &[u8],
        length: usize,
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}
