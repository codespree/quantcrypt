use crate::dsa::common::dsa_type::DsaType;
/// A trait to get the length of the public key

pub trait SigLen {
    fn get_sig_len(&self) -> Option<usize>;
}

impl SigLen for DsaType {
    /// Get the length of the signature
    ///
    /// # Returns
    ///
    /// The length of the signature in bytes
    fn get_sig_len(&self) -> Option<usize> {
        match self {
            DsaType::Rsa2048Pkcs15SHA256 => Some(256),
            DsaType::Rsa2048PssSHA256 => Some(256),
            DsaType::Rsa3072Pkcs15SHA512 => Some(384),
            DsaType::Rsa3072PssSHA512 => Some(384),

            DsaType::EcdsaP256SHA256 => None,
            DsaType::EcdsaP256SHA512 => None,
            DsaType::EcdsaP384SHA512 => None,
            DsaType::EcdsaBrainpoolP256r1SHA256 => None,
            DsaType::EcdsaBrainpoolP256r1SHA512 => None,
            DsaType::EcdsaBrainpoolP384r1SHA512 => None,
            DsaType::Ed25519SHA512 => Some(64),
            DsaType::Ed448SHA512 => Some(114),

            DsaType::MlDsa44 => Some(2420),
            DsaType::MlDsa65 => Some(3309),
            DsaType::MlDsa87 => Some(4627),

            // pq_pk + trad_pk + overhead
            DsaType::MlDsa44Rsa2048PssSha256 => Some(2420 + 256 + 14),
            DsaType::MlDsa44Rsa2048Pkcs15Sha256 => Some(2420 + 256 + 14),
            DsaType::MlDsa44Ed25519SHA512 => Some(2420 + 64 + 12),
            DsaType::MlDsa44EcdsaP256SHA256 => None,
            DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256 => None,
            DsaType::MlDsa65Rsa3072PssSHA512 => Some(3309 + 384 + 14),
            DsaType::MlDsa65Rsa3072Pkcs15SHA512 => Some(3309 + 384 + 14),
            DsaType::MlDsa65EcdsaP256SHA512 => None,
            DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512 => None,
            DsaType::MlDsa65Ed25519SHA512 => Some(3309 + 64 + 12),
            DsaType::MlDsa87EcdsaP384SHA512 => None,
            DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512 => None,
            DsaType::MlDsa87Ed448SHA512 => Some(4627 + 114 + 12),

            DsaType::SlhDsaSha2_128s => Some(7856),
            DsaType::SlhDsaSha2_128f => Some(17088),
            DsaType::SlhDsaSha2_192s => Some(16224),
            DsaType::SlhDsaSha2_192f => Some(35664),
            DsaType::SlhDsaSha2_256s => Some(29792),
            DsaType::SlhDsaSha2_256f => Some(49856),
            DsaType::SlhDsaShake128s => Some(7856),
            DsaType::SlhDsaShake128f => Some(17088),
            DsaType::SlhDsaShake192s => Some(16224),
            DsaType::SlhDsaShake192f => Some(35664),
            DsaType::SlhDsaShake256s => Some(29792),
            DsaType::SlhDsaShake256f => Some(49856),
        }
    }
}
