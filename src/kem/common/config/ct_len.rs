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
            // ML should be the following
            KemType::MlKem512 => Some(768),
            KemType::MlKem768 => Some(1088),
            KemType::MlKem1024 => Some(1568),
            // Old version
            // KEM CT + Trad CT + ASN.1 overhead
            KemType::MlKem512P256 => Some(768 + 65 + 10),
            KemType::MlKem512BrainpoolP256r1 => Some(768 + 65 + 10),
            KemType::MlKem512X25519 => Some(768 + 32 + 10),
            KemType::MlKem512Rsa2048 => Some(768 + 256 + 12),
            KemType::MlKem512Rsa3072 => Some(768 + 384 + 12),
            KemType::MlKem768P256 => Some(1088 + 65 + 10),
            KemType::MlKem768BrainpoolP256r1 => Some(1088 + 65 + 10),
            KemType::MlKem768X25519 => Some(1088 + 32 + 10),
            KemType::MlKem1024P384 => Some(1568 + 97 + 10),
            KemType::MlKem1024BrainpoolP384r1 => Some(1568 + 97 + 10),
            KemType::MlKem1024X448 => Some(1568 + 56 + 10),

            // Composite types from editor's draft. Skipped ones are also present in old version
            // Editor's copy
            KemType::MlKem768Rsa2048 => Some(1088 + 256 + 12),
            KemType::MlKem768Rsa3072 => Some(1088 + 384 + 12),
            KemType::MlKem768Rsa4096 => Some(1088 + 512 + 12),
            // KemType::MlKem768X25519 => None,
            KemType::MlKem768P384 => Some(1088 + 97 + 10),
            // KemType::MlKem768BrainpoolP256r1 => None,
            // KemType::MlKem1024P384 => None,
            // KemType::MlKem1024BrainpoolP384r1 => None,
            // KemType::MlKem1024X448 => None,
        }
    }
}
