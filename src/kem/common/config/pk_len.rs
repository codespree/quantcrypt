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
            KemType::P521 => Some(133),
            KemType::X448 => Some(56),
            // ML Key public key sizes
            KemType::MlKem512 => Some(800),
            KemType::MlKem768 => Some(1184),
            KemType::MlKem1024 => Some(1568),
            // RSA Key public key sizes
            KemType::RsaOAEP2048 => Some(270),
            KemType::RsaOAEP3072 => Some(398),
            KemType::RsaOAEP4096 => Some(526),

            // draft-15 composite public key = mlkemPK || tradPK (raw
            // concatenation, no ASN.1 wrapper). For ECDH components the
            // traditional public key is a fixed-size point, so the total is
            // exact. RSA public keys are DER-encoded and their length varies
            // slightly with leading-zero stripping, so those are `None`.
            KemType::MlKem768BrainpoolP256r1 => Some(1184 + 65),
            KemType::MlKem768X25519 => Some(1184 + 32),
            KemType::MlKem1024P384 => Some(1568 + 97),
            KemType::MlKem1024BrainpoolP384r1 => Some(1568 + 97),
            KemType::MlKem1024X448 => Some(1568 + 56),
            KemType::MlKem768Rsa2048 => None,
            KemType::MlKem768Rsa3072 => None,
            KemType::MlKem768Rsa4096 => None,
            KemType::MlKem768P256 => Some(1184 + 65),
            KemType::MlKem768P384 => Some(1184 + 97),
            KemType::MlKem1024Rsa3072 => None,
            KemType::MlKem1024P521 => Some(1568 + 133),

            KemType::XWing => Some(1216),
        }
    }
}
