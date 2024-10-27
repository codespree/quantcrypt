use crate::aead::common::aead_type::AeadType;

/// A trait to get the length of the key
pub trait KLen {
    fn get_k_len(&self) -> usize;
}

impl KLen for AeadType {
    /// Get the length of the key in bytes
    ///
    /// # Returns
    ///
    /// The length of the key in bytes
    fn get_k_len(&self) -> usize {
        match self {
            AeadType::AesGcm128 => 16,
            AeadType::AesGcm256 => 32,
        }
    }
}
