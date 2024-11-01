use crate::dsa::common::dsa_type::DsaType;
use crate::dsa::common::prehash_dsa_type::PrehashDsaType;
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
            DsaType::Rsa2048Pkcs15Sha256 => Some(270),
            DsaType::Rsa2048PssSha256 => Some(270),
            DsaType::Rsa3072Pkcs15Sha256 => Some(398),
            DsaType::Rsa3072PssSha256 => Some(398),
            // TODO: Fill in the rest of the public key lengths
            DsaType::Rsa4096Pkcs15Sha384 => None,
            DsaType::Rsa4096PssSha384 => None,

            DsaType::EcdsaP256SHA256 => Some(65),
            DsaType::EcdsaBrainpoolP256r1SHA256 => Some(65),

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

            //TODO:Fill these in
            DsaType::EcdsaP384SHA384 => None,
            DsaType::EcdsaBrainpoolP384r1SHA384 => None,
            DsaType::Ed25519 => None,
            DsaType::Ed448 => None,
        }
    }
}

impl PKLen for PrehashDsaType {
    /// Get the length of the public key
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes or `None` if the length is not fixed
    fn get_pk_len(&self) -> Option<usize> {
        match self {
            PrehashDsaType::MlDsa44 => Some(1312),
            PrehashDsaType::MlDsa65 => Some(1952),
            PrehashDsaType::MlDsa87 => Some(2592),

            // pq_pk + trad_pk + overhead
            PrehashDsaType::MlDsa44Rsa2048Pss => Some(1312 + 270 + 14),
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => Some(1312 + 270 + 14),
            PrehashDsaType::MlDsa44Ed25519 => Some(1312 + 32 + 12),
            PrehashDsaType::MlDsa44EcdsaP256 => Some(1312 + 65 + 12),
            PrehashDsaType::MlDsa65Rsa3072Pss => Some(1952 + 398 + 14),
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => Some(1952 + 398 + 14),
            PrehashDsaType::MlDsa65EcdsaP384 => None, //TODO: newly added, check manually
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => Some(1952 + 65 + 12),
            PrehashDsaType::MlDsa65Ed25519 => Some(1952 + 32 + 12),
            PrehashDsaType::MlDsa87EcdsaP384 => Some(2592 + 97 + 12),
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => Some(2592 + 97 + 12),
            PrehashDsaType::MlDsa87Ed448 => Some(2592 + 57 + 12),
            PrehashDsaType::MlDsa65Rsa4096Pss => None, //TODO: newly added, check manually
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => None, //TODO: newly added, check manually

            //TODO:Fill these in
            PrehashDsaType::MlDsa44Rsa2048PssSha256 => None,
            PrehashDsaType::MlDsa44Rsa2048Pkcs15Sha256 => None,
            PrehashDsaType::MlDsa44Ed25519Sha512 => None,
            PrehashDsaType::MlDsa44EcdsaP256Sha256 => None,
            PrehashDsaType::MlDsa65Rsa3072PssSha512 => None,
            PrehashDsaType::MlDsa65Rsa3072Pkcs15Sha512 => None,
            PrehashDsaType::MlDsa65Rsa4096PssSha512 => None,
            PrehashDsaType::MlDsa65Rsa4096Pkcs15Sha512 => None,
            PrehashDsaType::MlDsa65EcdsaP384Sha512 => None,
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1Sha512 => None,
            PrehashDsaType::MlDsa65Ed25519Sha512 => None,
            PrehashDsaType::MlDsa87EcdsaP384Sha512 => None,
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1Sha512 => None,
            PrehashDsaType::MlDsa87Ed448Sha512 => None,
        }
    }
}
