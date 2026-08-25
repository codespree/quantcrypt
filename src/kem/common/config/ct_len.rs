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
            KemType::P521 => Some(133),
            KemType::X448 => Some(56),
            // RSA is dependent on the key size
            KemType::RsaOAEP2048 => Some(256),
            KemType::RsaOAEP3072 => Some(384),
            KemType::RsaOAEP4096 => Some(512),
            // ML should be the following
            KemType::MlKem512 => Some(768),
            KemType::MlKem768 => Some(1088),
            KemType::MlKem1024 => Some(1568),

            // draft-15 composite ciphertext = mlkemCT || tradCT (raw
            // concatenation, no ASN.1 wrapper). Both ML-KEM ciphertexts and the
            // traditional ciphertexts (ECDH ephemeral point or RSA-OAEP block of
            // modulus size) are fixed length, so the totals are exact.
            KemType::MlKem768BrainpoolP256r1 => Some(1088 + 65),
            KemType::MlKem768X25519 => Some(1088 + 32),
            KemType::MlKem1024P384 => Some(1568 + 97),
            KemType::MlKem1024BrainpoolP384r1 => Some(1568 + 97),
            KemType::MlKem1024X448 => Some(1568 + 56),
            KemType::MlKem768Rsa2048 => Some(1088 + 256),
            KemType::MlKem768Rsa3072 => Some(1088 + 384),
            KemType::MlKem768Rsa4096 => Some(1088 + 512),
            KemType::MlKem768P384 => Some(1088 + 97),
            KemType::MlKem768P256 => Some(1088 + 65),
            KemType::MlKem1024Rsa3072 => Some(1568 + 384),
            // P-521 ciphertext (ephemeral point) is 133 bytes -> 2-byte DER
            // length, +11 framing (one more than the shorter curves' +10).
            KemType::MlKem1024P521 => Some(1568 + 133),
            KemType::XWing => Some(1120),
        }
    }
}
