use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::config::oids::Oid;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum PrehashDsaType {
    // Pure ML DSA
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // Hash ML DSA
    HashMlDsa44,
    HashMlDsa65,
    HashMlDsa87,

    // Pure ML-DSA Composite Signature Algorithms
    MlDsa44Rsa2048Pss,
    MlDsa44Rsa2048Pkcs15,
    MlDsa44Ed25519,
    MlDsa44EcdsaP256,
    MlDsa65Rsa3072Pss,
    MlDsa65Rsa3072Pkcs15,
    MlDsa65Rsa4096Pss,
    MlDsa65Rsa4096Pkcs15,
    MlDsa65EcdsaP384,
    MlDsa65EcdsaBrainpoolP256r1,
    MlDsa65Ed25519,
    MlDsa87EcdsaP384,
    MlDsa87EcdsaBrainpoolP384r1,
    MlDsa87Ed448,

    // Hash ML-DSA Composite Signature Algorithms
    HashMlDsa44Rsa2048PssSha256,
    HashMlDsa44Rsa2048Pkcs15Sha256,
    HashMlDsa44Ed25519Sha512,
    HashMlDsa44EcdsaP256Sha256,
    HashMlDsa65Rsa3072PssSha512,
    HashMlDsa65Rsa3072Pkcs15Sha512,
    HashMlDsa65Rsa4096PssSha512,
    HashMlDsa65Rsa4096Pkcs15Sha512,
    HashMlDsa65EcdsaP384Sha512,
    HashMlDsa65EcdsaBrainpoolP256r1Sha512,
    HashMlDsa65Ed25519Sha512,
    HashMlDsa87EcdsaP384Sha512,
    HashMlDsa87EcdsaBrainpoolP384r1Sha512,
    HashMlDsa87Ed448Sha512,

    // Pure SLH-DSA
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,

    // Prehash SLH-DSA
    HashSlhDsaSha2_128s,
    HashSlhDsaSha2_128f,
    HashSlhDsaSha2_192s,
    HashSlhDsaSha2_192f,
    HashSlhDsaSha2_256s,
    HashSlhDsaSha2_256f,
    HashSlhDsaShake128s,
    HashSlhDsaShake128f,
    HashSlhDsaShake192s,
    HashSlhDsaShake192f,
    HashSlhDsaShake256s,
    HashSlhDsaShake256f,
}

impl PrehashDsaType {
    pub fn all() -> Vec<PrehashDsaType> {
        PrehashDsaType::iter().collect()
    }

    pub fn is_composite(&self) -> bool {
        !matches!(
            self,
            PrehashDsaType::MlDsa44 | PrehashDsaType::MlDsa65 | PrehashDsaType::MlDsa87
        )
    }

    pub fn from_oid(oid: &str) -> Option<PrehashDsaType> {
        let all_dsa_types = PrehashDsaType::all();
        all_dsa_types
            .into_iter()
            .find(|dsa_type| dsa_type.get_oid() == oid)
    }
}
