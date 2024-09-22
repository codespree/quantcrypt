#[derive(Clone, Debug, PartialEq)]
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
}
