use crate::wrap::aes_wrap::Aes;
use crate::wrap::common::wrap_info::WrapInfo;
use crate::wrap::common::wrap_trait::Wrap;
use crate::wrap::common::wrap_type::WrapType;
use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

const WRAP_TYPES: [WrapType; 2] = [WrapType::Aes128, WrapType::Aes256];

// Implement clone
#[derive(Clone)]
/// Enum to representthe different types of KEM managers
pub enum WrapManager {
    /// AES wrap implementation
    Aes(Aes),
}

impl Wrap for WrapManager {
    fn new(wrap_type: WrapType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match wrap_type {
            _ if WRAP_TYPES.contains(&wrap_type) => WrapManager::Aes(Aes::new(wrap_type)?),
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn wrap(&self, wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>> {
        match self {
            WrapManager::Aes(aes) => aes.wrap(wrapping_key, key_to_wrap),
        }
    }

    fn unwrap(&self, wrapping_key: &[u8], key_to_unwrap: &[u8]) -> Result<Vec<u8>> {
        match self {
            WrapManager::Aes(aes) => aes.unwrap(wrapping_key, key_to_unwrap),
        }
    }

    fn get_wrap_info(&self) -> WrapInfo {
        match self {
            WrapManager::Aes(aes) => aes.get_wrap_info(),
        }
    }
}
