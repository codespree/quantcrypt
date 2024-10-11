use crate::kem::common::kem_type::KemType;

/// A trait to get the length of the ciphertext
pub trait CTLen {
    fn get_ct_len(&self) -> Option<usize>;
}

impl CTLen for KemType {
    /// Get the length of the ciphertext
    ///
    /// # Returns
    ///
    /// The length of the ciphertext in bytes
    fn get_ct_len(&self) -> Option<usize> {
        match self {
            KemType::P256 => Some(65),
            KemType::P384 => Some(97),
            KemType::X25519 => Some(32),
            KemType::BrainpoolP256r1 => Some(65),
            KemType::BrainpoolP384r1 => Some(97),
            KemType::X448 => Some(56),
            // RSA is dependent on the key size
            KemType::RsaOAEP2048 => Some(256),
            KemType::RsaOAEP3072 => Some(384),
            KemType::RsaOAEP4096 => Some(512),
            // ML varies
            KemType::MlKem512 => None,
            KemType::MlKem768 => None,
            KemType::MlKem1024 => None,
            // Composite also varies as ML varies
            // Old version
            KemType::MlKem512P256 => None,
            KemType::MlKem512BrainpoolP256r1 => None,
            KemType::MlKem512X25519 => None,
            KemType::MlKem512Rsa2048 => None,
            KemType::MlKem512Rsa3072 => None,
            KemType::MlKem768P256 => None,
            KemType::MlKem768BrainpoolP256r1 => None,
            KemType::MlKem768X25519 => None,
            KemType::MlKem1024P384 => None,
            KemType::MlKem1024BrainpoolP384r1 => None,
            KemType::MlKem1024X448 => None,
            // Editor's copy
            KemType::MlKem768Rsa2048 => None,
            KemType::MlKem768Rsa3072 => None,
            KemType::MlKem768Rsa4096 => None,
            // KemType::MlKem768X25519 => None,
            KemType::MlKem768P384 => None,
            // KemType::MlKem768BrainpoolP256r1 => None,
            // KemType::MlKem1024P384 => None,
            // KemType::MlKem1024BrainpoolP384r1 => None,
            // KemType::MlKem1024X448 => None,
        }
    }
}
