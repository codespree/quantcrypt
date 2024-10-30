use rand_core::CryptoRngCore;

use crate::{dsa::common::prehash_dsa_type::PrehashDsaType, QuantCryptError};

use super::prehash_dsa_info::PrehashDsaInfo;
use crate::dsa::common::config::oids::Oid;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A trait for DSA. All DSA implementations should implement this trait.
pub trait PrehashDsa {
    /// Create a new DSA instance
    ///
    /// # Arguments
    ///
    /// * `dsa_type` - The type of DSA to create
    ///
    /// # Returns
    ///
    /// A new DSA instance
    fn new(prehash_dsa_type: PrehashDsaType) -> Result<Self>
    where
        Self: Sized;

    /// Create a new DSA instance from an OID
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID of the DSA
    ///
    /// # Returns
    ///
    /// A new DSA instance
    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_dsa_types = PrehashDsaType::all();
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
    /// * `ctx` - The context to sign
    ///
    /// # Returns
    ///
    /// The signature of the message
    fn sign(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>>;

    /// Sign a message with prehash
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to sign the message
    /// * `msg` - The message to sign
    /// * `ctx` - The context to sign
    /// * `ph` - The Message Digest Algorithm for pre-hashing to sign
    ///
    /// # Returns
    ///
    /// The signature of the message
    fn sign_prehash(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>, ph: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to verify the signature
    /// * `msg` - The message to verify
    /// * `signature` - The signature to verify
    /// * `ctx` - The context to verify
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid
    fn verify(&self, pk: &[u8], msg: &[u8], signature: &[u8], ctx: Option<&[u8]>) -> Result<bool>;

    /// Verify a signature with prehash
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to verify the signature
    /// * `msg` - The message to verify
    /// * `signature` - The signature to verify
    /// * `ctx` - The context to verify
    /// * `ph` - The Message Digest Algorithm for pre-hashing to verify
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid
    fn verify_prehash(&self, pk: &[u8], msg: &[u8], signature: &[u8], ctx: Option<&[u8]>, ph: &[u8]) -> Result<bool>;

    /// Get DSA metadata information such as the key lengths,
    /// size of signature, etc.
    ///
    /// These values are also used to test the correctness of the DSA
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the DSA
    fn get_dsa_info(&self) -> PrehashDsaInfo;

    /// Get the public key from a secret key
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key
    ///
    /// # Returns
    ///
    /// The public key
    fn get_public_key(&self, sk: &[u8]) -> Result<Vec<u8>>;
}
