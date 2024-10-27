use crate::aead::aes_aead::AesAeadManager;
use crate::aead::common::aead_trait::Aead;
use crate::aead::common::aead_type::AeadType;
use crate::QuantCryptError;

use crate::aead::common::aead_info::AeadInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

const AEAD_TYPES: [AeadType; 2] = [AeadType::AesGcm128, AeadType::AesGcm256];

// Implement clone
#[derive(Clone)]
/// Enum to represent the different types of CEA managers
pub enum AeadManager {
    /// AES CEA implementation
    Aes(AesAeadManager),
}

impl Aead for AeadManager {
    fn new(aead_type: AeadType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match aead_type {
            _ if AEAD_TYPES.contains(&aead_type) => {
                AeadManager::Aes(AesAeadManager::new(aead_type)?)
            }
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadManager::Aes(aes) => aes.seal(key, nonce, aad, plaintext),
        }
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadManager::Aes(aes) => aes.open(key, nonce, aad, ciphertext),
        }
    }

    fn get_aead_info(&self) -> AeadInfo {
        match self {
            AeadManager::Aes(aes) => aes.get_aead_info(),
        }
    }
}
