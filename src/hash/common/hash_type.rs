use strum_macros::EnumIter;

/// Define the KDF types
#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum HashType {
    /// SHA256
    Sha256,
    /// SHA512
    Sha512,
}
