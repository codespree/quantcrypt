use crate::aead::common::aead_type::AeadType;

/// A trait to get the minimum length of the nonce
pub trait NMin {
    fn get_n_min(&self) -> usize;
}

impl NMin for AeadType {
    /// Get the minimum length of the nonce
    ///
    /// # Returns
    ///
    /// The minimum length of the nonce
    fn get_n_min(&self) -> usize {
        match self {
            AeadType::AesGcm128 => 12,
            AeadType::AesGcm256 => 12,
        }
    }
}
