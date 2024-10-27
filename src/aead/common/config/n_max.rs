use crate::aead::common::aead_type::AeadType;

/// A trait to get the maximum length of the nonce
pub trait NMAx {
    fn get_n_max(&self) -> usize;
}

impl NMAx for AeadType {
    /// Get the maximum length of the nonce
    ///
    /// # Returns
    ///
    /// The maximum length of the nonce
    fn get_n_max(&self) -> usize {
        match self {
            AeadType::AesGcm128 => 12,
            AeadType::AesGcm256 => 12,
        }
    }
}
