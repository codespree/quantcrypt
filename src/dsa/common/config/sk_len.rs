use crate::dsa::common::dsa_type::DsaType;
/// A trait to get the length of the public key

pub trait SKLen {
    fn get_sk_len(&self) -> Option<usize>;
}

impl SKLen for DsaType {
    /// Get the length of the private key
    ///
    /// # Returns
    ///
    /// The length of the private key in bytes or `None` if the length is not fixed
    fn get_sk_len(&self) -> Option<usize> {
        match self {
            DsaType::Rsa2048Pkcs15SHA256 => None,
            DsaType::Rsa2048PssSHA256 => None,
            DsaType::Rsa3072Pkcs15SHA512 => None,
            DsaType::Rsa3072PssSHA512 => None,

            DsaType::EcdsaP256SHA256 => Some(32),
            DsaType::EcdsaP256SHA512 => Some(32),
            DsaType::EcdsaP384SHA512 => Some(48),
            DsaType::EcdsaBrainpoolP256r1SHA256 => Some(32),
            DsaType::EcdsaBrainpoolP256r1SHA512 => Some(32),
            DsaType::EcdsaBrainpoolP384r1SHA512 => Some(48),
            DsaType::Ed25519SHA512 => Some(32),
            DsaType::Ed448SHA512 => Some(57),

            DsaType::MlDsa44 => Some(2560),
            DsaType::MlDsa65 => Some(4032),
            DsaType::MlDsa87 => Some(4896),

            // TODO: Investigate sk lengths
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
