use crate::aead::common::aead_info::AeadInfo;
use crate::{aead::common::aead_type::AeadType, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Aead {
    /// Create a new Aead instance
    ///
    /// # Arguments
    ///
    /// * `aead_type` - The type of AEAD to create
    fn new(aead_type: AeadType) -> Result<Self>
    where
        Self: Sized;

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Get AEAD metadata information such as the key lengths,
    /// size of ciphertext, etc.
    ///
    /// These values are also used to test the correctness of the AEAD
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the AEAD
    fn get_aead_info(&self) -> AeadInfo;
}
