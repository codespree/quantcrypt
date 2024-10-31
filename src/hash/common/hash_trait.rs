use crate::hash::common::hash_info::HashInfo;
use crate::{hash::common::hash_type::HashType, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Hash {
    /// Create a new hash instance
    ///
    /// # Arguments
    ///
    /// * `hash_type` - The type of hash to create
    fn new(hash_type: HashType) -> Result<Self>
    where
        Self: Sized;

    /// Get hash metadata information such as OID
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the hash
    fn get_hash_info(&self) -> HashInfo;

    /// Hash a message
    ///
    /// # Arguments
    ///
    /// * `message` - The message to hash
    ///
    /// # Returns
    ///
    /// The hash of the message
    fn hash(&self, message: &[u8]) -> Result<Vec<u8>>;
}
