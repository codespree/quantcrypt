use rand_core::CryptoRngCore;

use crate::kem::common::kem_info::KemInfo;
use crate::kem::common::kem_type::KemType;
use crate::QuantCryptError;

use crate::kem::common::config::oids::Oid;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, QuantCryptError>;

/// Key Encapsulation Mechanism (KEM) trait
pub trait Kem {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    fn new(kem_type: KemType) -> Result<Self>
    where
        Self: Sized;

    /// Generate a keypair using the default random number generator
    ///
    /// For EC based KEMs, the keypair is generated using the OpenSSL library using
    /// the default random number generator.
    ///
    /// For ML and RSA based KEMs, the keypair is generated usingvthe ChaCha20Rng
    /// random number generator.
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Generate a keypair with a specified random number generator
    ///
    /// # Arguments
    ///
    /// * `rng` - The random number generator to use
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the ciphertext and shared secret (ct, ss)
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a ciphertext
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to decapsulate with
    /// * `ct` - The ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The shared secret
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>>;

    /// Get KEM metadata information such as the key lengths,
    /// size of ciphertext, etc.
    ///
    /// These values are also used to test the correctness of the KEM
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the KEM
    fn get_kem_info(&self) -> KemInfo;

    /// Create a new KEM instance from an OID
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID of the KEM
    ///
    /// # Returns
    ///
    /// The new KEM instance
    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_kem_types = KemType::all();
        for kem_type in all_kem_types {
            if kem_type.get_oid() == oid {
                let kem = Self::new(kem_type)?;
                return Ok(kem);
            }
        }
        Err(QuantCryptError::InvalidOid)
    }
}
