use strum_macros::EnumIter;

/// Define the KDF types
#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum HashType {
    /// SHA256
    Sha256,
    /// SHA512
    Sha512,
    /// Shake 128
    Shake128,
    /// Shake 256
    Shake256,
    /// Shake 256 with a 64-byte (512-bit) XOF output (SHAKE256/64),
    /// used as the pre-hash for the MLDSA87-Ed448 composite (draft-19).
    Shake256_64,
}
