use crate::dsa::common::dsa_type::DsaType;
use crate::dsa::common::prehash_dsa_type::PrehashDsaType;
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
            DsaType::Rsa2048Pkcs15Sha256 => Some(256),
            DsaType::Rsa2048PssSha256 => Some(256),
            DsaType::Rsa3072Pkcs15Sha256 => Some(384),
            DsaType::Rsa3072PssSha256 => Some(384),
            DsaType::Rsa4096Pkcs15Sha384 => Some(512),
            DsaType::Rsa4096PssSha384 => Some(512),

            // P256 and P384 variations do not have a fixed sig_len
            DsaType::EcdsaP256SHA256 => None,
            DsaType::EcdsaBrainpoolP256r1SHA256 => None,
            DsaType::EcdsaP384SHA384 => None,
            DsaType::EcdsaBrainpoolP384r1SHA384 => None,

            DsaType::Ed25519 => Some(64),
            DsaType::Ed448 => Some(114),
        }
    }
}

impl SigLen for PrehashDsaType {
    /// Get the length of the signature
    ///
    /// # Returns
    ///
    /// The length of the signature in bytes
    fn get_sig_len(&self) -> Option<usize> {
        match self {
            PrehashDsaType::MlDsa44 => Some(2420),
            PrehashDsaType::MlDsa65 => Some(3309),
            PrehashDsaType::MlDsa87 => Some(4627),

            PrehashDsaType::HashMlDsa44 => Some(2420),
            PrehashDsaType::HashMlDsa65 => Some(3309),
            PrehashDsaType::HashMlDsa87 => Some(4627),

            // pq_pk + trad_pk + overhead
            PrehashDsaType::MlDsa44Rsa2048Pss => Some(2420 + 256 + 14), // 2690
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => Some(2420 + 256 + 14), // 2690
            PrehashDsaType::MlDsa44Ed25519 => Some(2420 + 64 + 12),     // 2496
            PrehashDsaType::MlDsa44EcdsaP256 => None,                   // None
            PrehashDsaType::MlDsa65Rsa3072Pss => Some(3309 + 384 + 14), // 3707
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => Some(3309 + 384 + 14), // 3707
            PrehashDsaType::MlDsa65Rsa4096Pss => Some(3309 + 512 + 14), // 3835
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => Some(3309 + 512 + 14), // 3835
            PrehashDsaType::MlDsa65EcdsaP384 => None,                   // None
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => None,        // None
            PrehashDsaType::MlDsa65Ed25519 => Some(3309 + 64 + 12),     // 3385
            PrehashDsaType::MlDsa87EcdsaP384 => None,                   // None
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => None,        // None
            PrehashDsaType::MlDsa87Ed448 => Some(4627 + 114 + 12),      // 4753

            PrehashDsaType::HashMlDsa44Rsa2048PssSha256 => Some(2420 + 256 + 14), // 2690
            PrehashDsaType::HashMlDsa44Rsa2048Pkcs15Sha256 => Some(2420 + 256 + 14), // 2690
            PrehashDsaType::HashMlDsa44Ed25519Sha512 => Some(2420 + 64 + 12),     // 2496
            PrehashDsaType::HashMlDsa44EcdsaP256Sha256 => None,                   // None
            PrehashDsaType::HashMlDsa65Rsa3072PssSha512 => Some(3309 + 384 + 14), // 3707
            PrehashDsaType::HashMlDsa65Rsa3072Pkcs15Sha512 => Some(3309 + 384 + 14), // 3707
            PrehashDsaType::HashMlDsa65Rsa4096PssSha512 => Some(3309 + 512 + 14), // 3835
            PrehashDsaType::HashMlDsa65Rsa4096Pkcs15Sha512 => Some(3309 + 512 + 14), // 3835
            PrehashDsaType::HashMlDsa65EcdsaP384Sha512 => None,                   // None
            PrehashDsaType::HashMlDsa65EcdsaBrainpoolP256r1Sha512 => None,        // None
            PrehashDsaType::HashMlDsa65Ed25519Sha512 => Some(3309 + 64 + 12),     // 3385
            PrehashDsaType::HashMlDsa87EcdsaP384Sha512 => None,                   // None
            PrehashDsaType::HashMlDsa87EcdsaBrainpoolP384r1Sha512 => None,        // None
            PrehashDsaType::HashMlDsa87Ed448Sha512 => Some(4627 + 114 + 12),      // 4753

            // Pure SLH-DSA, aligned with fips205 implementation
            PrehashDsaType::SlhDsaSha2_128s => Some(7856),
            PrehashDsaType::SlhDsaSha2_128f => Some(17088),
            PrehashDsaType::SlhDsaSha2_192s => Some(16224),
            PrehashDsaType::SlhDsaSha2_192f => Some(35664),
            PrehashDsaType::SlhDsaSha2_256s => Some(29792),
            PrehashDsaType::SlhDsaSha2_256f => Some(49856),
            PrehashDsaType::SlhDsaShake128s => Some(7856),
            PrehashDsaType::SlhDsaShake128f => Some(17088),
            PrehashDsaType::SlhDsaShake192s => Some(16224),
            PrehashDsaType::SlhDsaShake192f => Some(35664),
            PrehashDsaType::SlhDsaShake256s => Some(29792),
            PrehashDsaType::SlhDsaShake256f => Some(49856),

            // Prehash SLH-DSA
            PrehashDsaType::HashSlhDsaSha2_128s => Some(7856),
            PrehashDsaType::HashSlhDsaSha2_128f => Some(17088),
            PrehashDsaType::HashSlhDsaSha2_192s => Some(16224),
            PrehashDsaType::HashSlhDsaSha2_192f => Some(35664),
            PrehashDsaType::HashSlhDsaSha2_256s => Some(29792),
            PrehashDsaType::HashSlhDsaSha2_256f => Some(49856),
            PrehashDsaType::HashSlhDsaShake128s => Some(7856),
            PrehashDsaType::HashSlhDsaShake128f => Some(17088),
            PrehashDsaType::HashSlhDsaShake192s => Some(16224),
            PrehashDsaType::HashSlhDsaShake192f => Some(35664),
            PrehashDsaType::HashSlhDsaShake256s => Some(29792),
            PrehashDsaType::HashSlhDsaShake256f => Some(49856),
        }
    }
}
