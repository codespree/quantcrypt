use crate::wrap::common::wrap_type::WrapType;

/// A trait to get the OID of a key wrapping algorithm
pub trait KeyLength {
    /// Get the key length for the key wrapping algorithm
    ///
    /// # Returns
    ///
    /// The length for the key wrapping algorithm
    fn get_key_length(&self) -> u16;
}

impl KeyLength for WrapType {
    /// Get the key length for the key wrapping algorithm
    ///
    /// # Returns
    ///
    /// The length for the key wrapping algorithm
    fn get_key_length(&self) -> u16 {
        match self {
            WrapType::Aes128 => 16,
            WrapType::Aes256 => 32,
        }
    }
}
