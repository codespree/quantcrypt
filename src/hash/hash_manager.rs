use crate::hash::common::hash_trait::Hash;
use crate::hash::common::hash_type::HashType;
use crate::hash::sha_hash::ShaHash;
use crate::QuantCryptError;

use crate::hash::common::hash_info::HashInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

// Implement clone
#[derive(Clone)]
/// Enum to represent the different types of hash managers
pub enum HashManager {
    /// AES CEA implementation
    Sha(ShaHash),
}

impl Hash for HashManager {
    fn new(hash_type: HashType) -> Result<Self>
    where
        Self: Sized,
    {
        match hash_type {
            HashType::Sha256 | HashType::Sha512 => Ok(HashManager::Sha(ShaHash::new(hash_type)?)),
        }
    }

    fn get_hash_info(&self) -> HashInfo {
        match self {
            HashManager::Sha(hash) => hash.get_hash_info(),
        }
    }

    fn hash(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            HashManager::Sha(hash) => hash.hash(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::common::hash_type::HashType;

    #[test]
    fn test_hash_new() {
        let hash_manager = HashManager::new(HashType::Sha256).unwrap();
        assert_eq!(hash_manager.get_hash_info().hash_type, HashType::Sha256);
    }

    #[test]
    fn test_hash() {
        let hash_manager = HashManager::new(HashType::Sha256).unwrap();
        let message = b"hello world";
        let hash = hash_manager.hash(message).unwrap();
        assert_eq!(hash.len(), 32);

        let hash_manager = HashManager::new(HashType::Sha512).unwrap();
        let message = b"hello world";
        let hash = hash_manager.hash(message).unwrap();
        assert_eq!(hash.len(), 64);
    }
}
