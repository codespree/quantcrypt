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

            // pq_pk + trad_pk + overhead
            DsaType::MlDsa44Rsa2048PssSha256 => None,
            DsaType::MlDsa44Rsa2048Pkcs15Sha256 => None,
            DsaType::MlDsa44Ed25519SHA512 => Some(1312 + 32 + 12),
            DsaType::MlDsa44EcdsaP256SHA256 => Some(1312 + 65 + 12),
            DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256 => Some(1312 + 65 + 12),
            DsaType::MlDsa65Rsa3072PssSHA512 => None,
            DsaType::MlDsa65Rsa3072Pkcs15SHA512 => None,
            DsaType::MlDsa65EcdsaP256SHA512 => Some(1952 + 65 + 12),
            DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512 => Some(1952 + 65 + 12),
            DsaType::MlDsa65Ed25519SHA512 => Some(1952 + 32 + 12),
            DsaType::MlDsa87EcdsaP384SHA512 => Some(2592 + 97 + 12),
            DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512 => Some(2592 + 97 + 12),
            DsaType::MlDsa87Ed448SHA512 => Some(2592 + 57 + 12),

            DsaType::SlhDsaSha2_128s => Some(32),
            DsaType::SlhDsaSha2_128f => Some(32),
            DsaType::SlhDsaSha2_192s => Some(48),
            DsaType::SlhDsaSha2_192f => Some(48),
            DsaType::SlhDsaSha2_256s => Some(64),
            DsaType::SlhDsaSha2_256f => Some(64),
            DsaType::SlhDsaShake128s => Some(32),
            DsaType::SlhDsaShake128f => Some(32),
            DsaType::SlhDsaShake192s => Some(48),
            DsaType::SlhDsaShake192f => Some(48),
            DsaType::SlhDsaShake256s => Some(64),
            DsaType::SlhDsaShake256f => Some(64),
        }
    }
}
