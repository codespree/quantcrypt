use crate::aead::common::aead_type::AeadType;

/// A trait to get the length of the largest ciphertext that can be decrypted
pub trait CMax {
    fn get_c_max(&self) -> usize;
}

impl CMax for AeadType {
    /// Get the length of the largest ciphertext that can be decrypted
    ///
    /// # Returns
    ///
    /// The length of the largest ciphertext that can be decrypted
    fn get_c_max(&self) -> usize {
        match self {
            AeadType::AesGcm128 => (1 << 36) - 15,
            AeadType::AesGcm256 => (1 << 36) - 15,
        }
    }
}
