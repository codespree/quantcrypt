use crate::kem::common::kem_type::KemType;

/// A trait to get the length of the secret key
///
/// This is used to determine the length of the secret key
///
/// # Returns
///
/// The length of the secret key in bytes or `None` if the length is variable
pub trait SKLen {
    fn get_sk_len(&self) -> Option<usize>;
}

impl SKLen for KemType {
    /// Get the length of the secret key
    ///
    /// # Returns
    ///
    /// The length of the secret key in bytes or `None` if the length is not fixed
    fn get_sk_len(&self) -> Option<usize> {
        match self {
            // These are Nsk length as per SerializePrivateKey(skX)
            // in RFC 9180
            KemType::P256 => Some(32),
            KemType::P384 => Some(48),
            KemType::X25519 => Some(32),
            KemType::BrainpoolP256r1 => Some(32),
            KemType::BrainpoolP384r1 => Some(48),
            KemType::X448 => Some(56),
            // ML Key secret key sizes
            KemType::MlKem512 => Some(1632),
            KemType::MlKem768 => Some(2400),
            KemType::MlKem1024 => Some(3168),
            // RSA Key secret key sizes
            KemType::RsaOAEP2048 => None,
            KemType::RsaOAEP3072 => None,
            KemType::RsaOAEP4096 => None,
            // Composite types from old version
            // TODO: If there is a fixed size, then it should be added here
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
            // Composite types from editor's draft. Skipped ones are also present in old version
            // TODO: If there is a fixed size, then it should be added here
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
