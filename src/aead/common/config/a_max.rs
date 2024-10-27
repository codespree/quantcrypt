use crate::aead::common::aead_type::AeadType;

/// A trait to get the max length of the associated data
pub trait AMax {
    fn get_a_max(&self) -> usize;
}

impl AMax for AeadType {
    /// Get the max length of the associated data
    ///
    /// # Returns
    ///
    /// The max length of the associated data
    fn get_a_max(&self) -> usize {
        match self {
            AeadType::AesGcm128 => (1 << 61) - 1,
            AeadType::AesGcm256 => (1 << 61) - 1,
        }
    }
}
