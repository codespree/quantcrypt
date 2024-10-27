use crate::aead::common::aead_type::AeadType;

/// A trait to get the length of the largest plaintext that can be encrypted
pub trait PMax {
    fn get_p_max(&self) -> usize;
}

impl PMax for AeadType {
    /// Get the length of the largest plaintext that can be encrypted
    ///
    /// # Returns
    ///
    /// The length of the largest plaintext that can be encrypted
    fn get_p_max(&self) -> usize {
        match self {
            AeadType::AesGcm128 => (1 << 36) - 31,
            AeadType::AesGcm256 => (1 << 36) - 31,
        }
    }
}
