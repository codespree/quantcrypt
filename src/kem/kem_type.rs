pub enum KemType {
    /// NIST P-256 key encapsulation mechanism
    P256,
    /// NIST P-384 key encapsulation mechanism
    P384,
    /// X25519 key encapsulation mechanism
    X25519,
    /// MlKem512 key encapsulation mechanism
    MlKem512,
    /// MlKem768 key encapsulation mechanism
    MlKem768,
    /// MlKem1024 key encapsulation mechanism
    MlKem1024,
    /// RSA 2048 key encapsulation mechanism
    RsaOAEP2048,
    /// RSA 3072 key encapsulation mechanism
    RsaOAEP3072,
    /// BrainpoolP256r1 key encapsulation mechanism
    BrainpoolP256r1,
    /// BrainpoolP384r1 key encapsulation mechanism
    BrainpoolP384r1,
}
