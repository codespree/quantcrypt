use openssl::hash::{Hasher, MessageDigest};

use crate::hash::common::hash_info::HashInfo;
use crate::hash::common::hash_trait::Hash;
use crate::hash::common::hash_type::HashType;
use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

// Implement clone
#[derive(Clone)]
pub struct ShaHash {
    hash_type: HashType,
    digest: MessageDigest,
}

impl Hash for ShaHash {
    fn new(hash_type: HashType) -> Result<Self>
    where
        Self: Sized,
    {
        let digest = match hash_type {
            HashType::Sha256 => MessageDigest::sha256(),
            HashType::Sha512 => MessageDigest::sha512(),
            HashType::Shake128 => MessageDigest::shake_128(),
            HashType::Shake256 => MessageDigest::shake_256(),
        };

        Ok(ShaHash { hash_type, digest })
    }

    fn get_hash_info(&self) -> HashInfo {
        HashInfo::new(self.hash_type.clone())
    }

    fn hash(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Hasher::new(self.digest).map_err(|_| QuantCryptError::Unknown)?;
        hasher
            .update(message)
            .map_err(|_| QuantCryptError::Unknown)?;
        let msg = hasher.finish().map_err(|_| QuantCryptError::Unknown)?;
        Ok(msg.to_vec())
    }
}
