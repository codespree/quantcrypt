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

            // TODO: Investigate sig lengths
            DsaType::MlDsa44Rsa2048PssSha256 => None,
            DsaType::MlDsa44Rsa2048Pkcs15Sha256 => None,
            DsaType::MlDsa44Ed25519SHA512 => None,
            DsaType::MlDsa44EcdsaP256SHA256 => None,
            DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256 => None,
            DsaType::MlDsa65Rsa3072PssSHA512 => None,
            DsaType::MlDsa65Rsa3072Pkcs15SHA512 => None,
            DsaType::MlDsa65EcdsaP256SHA512 => None,
            DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512 => None,
            DsaType::MlDsa65Ed25519SHA512 => None,
            DsaType::MlDsa87EcdsaP384SHA512 => None,
            DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512 => None,
            DsaType::MlDsa87Ed448SHA512 => None,
        }
    }
}
