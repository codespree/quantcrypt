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
            DsaType::Rsa4096Pkcs15Sha384 => Some(526),
            DsaType::Rsa4096PssSha384 => Some(526),

            DsaType::EcdsaP256SHA256 => Some(65),
            DsaType::EcdsaBrainpoolP256r1SHA256 => Some(65),

            DsaType::EcdsaP384SHA384 => Some(97),
            DsaType::EcdsaBrainpoolP384r1SHA384 => Some(97),
            DsaType::Ed25519 => Some(32),
            DsaType::Ed448 => Some(57),
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

            PrehashDsaType::HashMlDsa44 => Some(1312),
            PrehashDsaType::HashMlDsa65 => Some(1952),
            PrehashDsaType::HashMlDsa87 => Some(2592),

            // pq_pk + trad_pk + overhead of sequence of two bit strings
            PrehashDsaType::MlDsa44Rsa2048Pss => Some(1312 + 270 + 14), // 1596
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => Some(1312 + 270 + 14), // 1596
            PrehashDsaType::MlDsa44Ed25519 => Some(1312 + 32 + 12),     // 1356
            PrehashDsaType::MlDsa44EcdsaP256 => Some(1312 + 65 + 12),   // 1389
            PrehashDsaType::MlDsa65Rsa3072Pss => Some(1952 + 398 + 14), // 2364
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => Some(1952 + 398 + 14), // 2364
            PrehashDsaType::MlDsa65Rsa4096Pss => Some(1952 + 526 + 14), // 2492
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => Some(1952 + 526 + 14), // 2492
            PrehashDsaType::MlDsa65EcdsaP384 => Some(1952 + 97 + 12),   // 2061
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => Some(1952 + 65 + 12), // 2029
            PrehashDsaType::MlDsa65Ed25519 => Some(1952 + 32 + 12),     // 1996
            PrehashDsaType::MlDsa87EcdsaP384 => Some(2592 + 97 + 12),   // 2701
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => Some(2592 + 97 + 12), // 2701
            PrehashDsaType::MlDsa87Ed448 => Some(2592 + 57 + 12),       // 2523

            PrehashDsaType::HashMlDsa44Rsa2048PssSha256 => Some(1312 + 270 + 14), // 1596
            PrehashDsaType::HashMlDsa44Rsa2048Pkcs15Sha256 => Some(1312 + 270 + 14), // 1596
            PrehashDsaType::HashMlDsa44Ed25519Sha512 => Some(1312 + 32 + 12),     // 1356
            PrehashDsaType::HashMlDsa44EcdsaP256Sha256 => Some(1312 + 65 + 12),   // 1389
            PrehashDsaType::HashMlDsa65Rsa3072PssSha512 => Some(1952 + 398 + 14), // 2364
            PrehashDsaType::HashMlDsa65Rsa3072Pkcs15Sha512 => Some(1952 + 398 + 14), // 2364
            PrehashDsaType::HashMlDsa65Rsa4096PssSha512 => Some(1952 + 526 + 14), // 2492
            PrehashDsaType::HashMlDsa65Rsa4096Pkcs15Sha512 => Some(1952 + 526 + 14), // 2492
            PrehashDsaType::HashMlDsa65EcdsaP384Sha512 => Some(1952 + 97 + 12),   // 2061
            PrehashDsaType::HashMlDsa65EcdsaBrainpoolP256r1Sha512 => Some(1952 + 65 + 12), // 2029
            PrehashDsaType::HashMlDsa65Ed25519Sha512 => Some(1952 + 32 + 12),     // 1996
            PrehashDsaType::HashMlDsa87EcdsaP384Sha512 => Some(2592 + 97 + 12),   // 2701
            PrehashDsaType::HashMlDsa87EcdsaBrainpoolP384r1Sha512 => Some(2592 + 97 + 12), // 2701
            PrehashDsaType::HashMlDsa87Ed448Sha512 => Some(2592 + 57 + 12),       // 2523

            // Pure SLH-DSA, aligned with fips205 implementation
            PrehashDsaType::SlhDsaSha2_128s => Some(32),
            PrehashDsaType::SlhDsaSha2_128f => Some(32),
            PrehashDsaType::SlhDsaSha2_192s => Some(48),
            PrehashDsaType::SlhDsaSha2_192f => Some(48),
            PrehashDsaType::SlhDsaSha2_256s => Some(64),
            PrehashDsaType::SlhDsaSha2_256f => Some(64),
            PrehashDsaType::SlhDsaShake128s => Some(32),
            PrehashDsaType::SlhDsaShake128f => Some(32),
            PrehashDsaType::SlhDsaShake192s => Some(48),
            PrehashDsaType::SlhDsaShake192f => Some(48),
            PrehashDsaType::SlhDsaShake256s => Some(64),
            PrehashDsaType::SlhDsaShake256f => Some(64),

            // Prehash SLH-DSA
            PrehashDsaType::HashSlhDsaSha2_128s => Some(32),
            PrehashDsaType::HashSlhDsaSha2_128f => Some(32),
            PrehashDsaType::HashSlhDsaSha2_192s => Some(48),
            PrehashDsaType::HashSlhDsaSha2_192f => Some(48),
            PrehashDsaType::HashSlhDsaSha2_256s => Some(64),
            PrehashDsaType::HashSlhDsaSha2_256f => Some(64),
            PrehashDsaType::HashSlhDsaShake128s => Some(32),
            PrehashDsaType::HashSlhDsaShake128f => Some(32),
            PrehashDsaType::HashSlhDsaShake192s => Some(48),
            PrehashDsaType::HashSlhDsaShake192f => Some(48),
            PrehashDsaType::HashSlhDsaShake256s => Some(64),
            PrehashDsaType::HashSlhDsaShake256f => Some(64),
        }
    }
}
