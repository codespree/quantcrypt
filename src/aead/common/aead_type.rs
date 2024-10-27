// RFC RFC5116
use strum_macros::EnumIter;

/// Define the KDF types
#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum AeadType {
    /// AES-GCM 128
    AesGcm128,
    /// AES-GCM 256
    AesGcm256,
}
