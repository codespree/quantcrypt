use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum DsaType {
    // RSA
    Rsa2048PssSHA256,
    Rsa2048Pkcs15SHA256,
    Rsa3072PssSHA512,
    Rsa3072Pkcs15SHA512,

    // ECDSA
    EcdsaP256SHA256,
    EcdsaP256SHA512,
    EcdsaP384SHA512,
    EcdsaBrainpoolP256r1SHA512,
    EcdsaBrainpoolP256r1SHA256,
    EcdsaBrainpoolP384r1SHA512,
    Ed25519SHA512,
    Ed448SHA512,

    // ML DSA
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // Composite DSAs
    MlDsa44Rsa2048PssSha256,
    MlDsa44Rsa2048Pkcs15Sha256,
    MlDsa44Ed25519SHA512,
    MlDsa44EcdsaP256SHA256,
    MlDsa44EcdsaBrainpoolP256r1SHA256,
    MlDsa65Rsa3072PssSHA512,
    MlDsa65Rsa3072Pkcs15SHA512,
    MlDsa65EcdsaP256SHA512,
    MlDsa65EcdsaBrainpoolP256r1SHA512,
    MlDsa65Ed25519SHA512,
    MlDsa87EcdsaP384SHA512,
    MlDsa87EcdsaBrainpoolP384r1SHA512,
    MlDsa87Ed448SHA512,
    // id-Falon512-ECDSA-P256-SHA256 //TODO: Unsupported
    // id-Falcon512-ECDSA-brainpoolP256r1-SHA256 //TODO: Unsupported
    // id-Falcon512-Ed25519-SHA512 //TODO: Unsupported
}

impl DsaType {
    pub fn all() -> Vec<DsaType> {
        DsaType::iter().collect()
    }
}
