use crate::kem::common::kem_type::KemType;

/// A trait to get the length of the public key
pub trait PKLen {
    fn get_pk_len(&self) -> Option<usize>;
}

impl PKLen for KemType {
    /// Get the length of the public key
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes or `None` if the length is not fixed
    fn get_pk_len(&self) -> Option<usize> {
        match self {
            // These are Npk length as per SerializePublicKey(pkX)
            // in RFC 9180
            KemType::P256 => Some(65),
            KemType::P384 => Some(97),
            KemType::X25519 => Some(32),
            KemType::BrainpoolP256r1 => Some(65),
            KemType::BrainpoolP384r1 => Some(97),
            KemType::X448 => Some(56),
            // ML Key public key sizes
            KemType::MlKem512 => Some(800),
            KemType::MlKem768 => Some(1184),
            KemType::MlKem1024 => Some(1568),
            // TODO: Confirm if RSA key format is correct
            KemType::RsaOAEP2048 => None,
            KemType::RsaOAEP3072 => None,
            KemType::RsaOAEP4096 => None,
            // Composite types
            // TODO: If there is a fixed size, then it should be added here
            KemType::MlKem768Rsa2048 => None,
            KemType::MlKem768Rsa3072 => None,
            KemType::MlKem768Rsa4096 => None,
            KemType::MlKem768X25519 => None,
            KemType::MlKem768P384 => None,
            KemType::MlKem768BrainpoolP256r1 => None,
            KemType::MlKem1024P384 => None,
            KemType::MlKem1024BrainpoolP384r1 => None,
            KemType::MlKem1024X448 => None,
        }
    }
}
