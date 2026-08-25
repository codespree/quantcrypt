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
            DsaType::EcdsaP521SHA512 => Some(133),
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

            // draft-19 composite public key = mldsaPK || tradPK (raw
            // concatenation, no ASN.1 wrapper). ECDSA/EdDSA traditional public
            // keys are fixed-size points, so the total is exact. RSA public keys
            // are DER-encoded and vary slightly in length, so those are `None`.
            PrehashDsaType::MlDsa44Rsa2048Pss => None,
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => None,
            PrehashDsaType::MlDsa44Ed25519 => Some(1312 + 32), // 1344
            PrehashDsaType::MlDsa44EcdsaP256 => Some(1312 + 65), // 1377
            PrehashDsaType::MlDsa65Rsa3072Pss => None,
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => None,
            PrehashDsaType::MlDsa65Rsa4096Pss => None,
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => None,
            PrehashDsaType::MlDsa65EcdsaP256 => Some(1952 + 65), // 2017
            PrehashDsaType::MlDsa65EcdsaP384 => Some(1952 + 97), // 2049
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => Some(1952 + 65), // 2017
            PrehashDsaType::MlDsa65Ed25519 => Some(1952 + 32),   // 1984
            PrehashDsaType::MlDsa87EcdsaP384 => Some(2592 + 97), // 2689
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => Some(2592 + 97), // 2689
            PrehashDsaType::MlDsa87Ed448 => Some(2592 + 57),     // 2649
            PrehashDsaType::MlDsa87Rsa3072Pss => None,
            PrehashDsaType::MlDsa87Rsa4096Pss => None,
            PrehashDsaType::MlDsa87EcdsaP521 => Some(2592 + 133), // 2725

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
