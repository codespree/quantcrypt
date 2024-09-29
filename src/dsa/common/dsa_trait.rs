use rand_core::CryptoRngCore;

use crate::{dsa::common::dsa_type::DsaType, QuantCryptError};

use super::dsa_info::DsaInfo;
use crate::dsa::common::config::oids::Oid;

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Dsa {
    /// Create a new DSA instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    /// * `seed` - A 32-byte seed
    fn new(dsa_type: DsaType) -> Result<Self>
    where
        Self: Sized;

    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_dsa_types = DsaType::all();
        for dsa_type in all_dsa_types {
            if dsa_type.get_oid() == oid {
                let dsa = Self::new(dsa_type)?;
                return Ok(dsa);
            }
        }
        Err(QuantCryptError::InvalidOid)
    }

    /// Generate a keypair using the default RNG of OpenSSL
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk).
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Generate a keypair using the specified RNG
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk).
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to sign the message
    /// * `msg` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature of the message
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to verify the signature
    /// * `msg` - The message to verify
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid
    fn verify(&self, pk: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool>;

    /// Get DSA metadata information such as the key lengths,
    /// size of signature, etc.
    ///
    /// These values are also used to test the correctness of the DSA
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the DSA
    fn get_dsa_info(&self) -> DsaInfo;
}
