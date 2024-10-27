use crate::aead::common::aead_type::AeadType;
use crate::aead::common::config::a_max::AMax;
use crate::aead::common::config::c_max::CMax;
use crate::aead::common::config::k_len::KLen;
use crate::aead::common::config::n_max::NMAx;
use crate::aead::common::config::n_min::NMin;
use crate::aead::common::config::p_max::PMax;

/// A structure to represent metadata about a AEAD
///
/// This is also used to test the correctness of the AEAD
#[derive(Clone)]
#[allow(dead_code)]
pub struct AeadInfo {
    /// The type of AEAD
    pub aead_type: AeadType,
    /// The length of the key in bytes
    pub k_byte_len: usize,
    /// The minimum length of the nonce
    pub n_min: usize,
    /// The maximum length of the nonce
    pub n_max: usize,
    /// The maximum length of the additional data
    pub a_max: usize,
    /// The maximum length of the ciphertext
    pub c_max: usize,
    /// The maximum length of the plaintext
    pub p_max: usize,
}

impl AeadInfo {
    /// AeadInfo a new `AeadInfo` structure
    ///
    /// # Arguments
    ///
    /// * `aead_type` - The type of AEAD
    pub fn new(aead_type: AeadType) -> AeadInfo {
        AeadInfo {
            aead_type: aead_type.clone(),
            k_byte_len: aead_type.get_k_len(),
            n_min: aead_type.get_n_min(),
            n_max: aead_type.get_n_max(),
            a_max: aead_type.get_a_max(),
            c_max: aead_type.get_c_max(),
            p_max: aead_type.get_p_max(),
        }
    }
}
