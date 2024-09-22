use crate::dsa::common::dsa_type::DsaType;
/// A trait to get the length of the public key

pub trait PKLen {
    fn get_pk_len(&self) -> Option<usize>;
}

impl PKLen for DsaType {
    /// Get the length of the public key
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes or `None` if the length is not fixed
    fn get_pk_len(&self) -> Option<usize> {
        match self {
            DsaType::Rsa2048Pkcs15SHA256 => None,
            DsaType::Rsa2048PssSHA256 => None,
            DsaType::Rsa3072Pkcs15SHA512 => None,
            DsaType::Rsa3072PssSHA512 => None,

            DsaType::EcdsaP256SHA256 => Some(65),
            DsaType::EcdsaP256SHA512 => Some(65),
            DsaType::EcdsaP384SHA512 => Some(97),
            DsaType::EcdsaBrainpoolP256r1SHA256 => Some(65),
            DsaType::EcdsaBrainpoolP256r1SHA512 => Some(65),
            DsaType::EcdsaBrainpoolP384r1SHA512 => Some(97),
            DsaType::Ed25519SHA512 => Some(32),
            DsaType::Ed448SHA512 => Some(57),

            DsaType::MlDsa44 => Some(1312),
            DsaType::MlDsa65 => Some(1952),
            DsaType::MlDsa87 => Some(2592),
        }
    }
}
