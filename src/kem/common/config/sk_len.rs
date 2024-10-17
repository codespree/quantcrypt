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
        // There is an extra offset of 2 bytes for ipd versions of ML-KEM composites:
        // ML-KEM composite ipd overhead: 26 bytes
        // ML-KEM composite latest overhead: 24 bytes
        #[cfg(feature = "ipd")]
        let ipd_offset = 2;
        
        #[cfg(not(feature = "ipd"))]
        let ipd_offset = 0;

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
            // RSA Key secret key sizes: varied
            KemType::RsaOAEP2048 => None,
            KemType::RsaOAEP3072 => None,
            KemType::RsaOAEP4096 => None,
            // Composite types from old version
            // KEM Sk + Trad Sk + ASN.1 overhead                       
            KemType::MlKem512P256 => Some(1632 + 32 + 118 + ipd_offset),                             
            KemType::MlKem512BrainpoolP256r1 => Some(1632 + 32 + 118 + ipd_offset),                 
            KemType::MlKem512X25519 => Some(1632 + 32 + 85 + ipd_offset),
            KemType::MlKem512Rsa2048 => None,
            KemType::MlKem512Rsa3072 => None,           
            KemType::MlKem768P256 => Some(2400 + 32 + 118 + ipd_offset),
            KemType::MlKem768BrainpoolP256r1 => Some(2400 + 32 + 118 + ipd_offset),
            KemType::MlKem768X25519 => Some(2400 + 32 + 85 + ipd_offset),
            KemType::MlKem1024P384 => Some(3168 + 48 + 151 + ipd_offset),
            KemType::MlKem1024BrainpoolP384r1 => Some(3168 + 48 + 151 + ipd_offset),
            KemType::MlKem1024X448 => Some(3168 + 56 + 110 + ipd_offset),
            // Composite types from editor's draft. Skipped ones are also present in old version
            // KEM Sk + Trad Sk + ASN.1 overhead
            KemType::MlKem768Rsa2048 => None,
            KemType::MlKem768Rsa3072 => None,
            KemType::MlKem768Rsa4096 => None,
            // KemType::MlKem768X25519 => Some(2400 + 32 + 85 + ipd_offset),
            KemType::MlKem768P384 => Some(2400 + 48 + 151  + ipd_offset),
            // KemType::MlKem768BrainpoolP256r1 => Some(2400 + 32 + 118 + ipd_offset),
            // KemType::MlKem1024P384 => Some(3168 + 48 + 151 + ipd_offset),
            // KemType::MlKem1024BrainpoolP384r1 => Some(3168 + 48 + 151 + ipd_offset),
            // KemType::MlKem1024X448 => Some(3168 + 56 + 110 + ipd_offset),
        }
    }
}
