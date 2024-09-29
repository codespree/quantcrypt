use crate::asn1::private_key::PrivateKey;
use crate::asn1::public_key::PublicKey;
use crate::errors;
use crate::kem::common::config::oids::Oid;
use crate::kem::{api::algorithm::KemAlgorithm, common::kem_trait::Kem, kem_manager::KemManager};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, errors::QuantCryptError>;

/// A key generator for DSA keys
///
/// # Example
/// ```
/// use quantcrypt::KemKeyGenerator;
/// use quantcrypt::KemAlgorithm;
///
/// let mut key_generator = KemKeyGenerator::new(KemAlgorithm::MlKem768);
/// let (pk, sk) = key_generator.generate().unwrap();
/// ```
pub struct KemKeyGenerator {
    /// The algorithm to use for key generation
    algorithm: KemAlgorithm,
}

impl KemKeyGenerator {
    /// Create a new `KeyGenerator` with the specified algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to use for key generation
    ///
    /// # Returns
    ///
    /// The new `KeyGenerator`
    pub fn new(algorithm: KemAlgorithm) -> KemKeyGenerator {
        KemKeyGenerator { algorithm }
    }

    /// Generate a keypair using the default RNG
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    pub fn generate(&mut self) -> Result<(PublicKey, PrivateKey)> {
        let kem_type = self.algorithm.get_kem_type();
        let mut dsa_manager = KemManager::new(kem_type.clone())?;
        let (pk, sk) = dsa_manager
            .key_gen()
            .map_err(|_| errors::QuantCryptError::KeyPairGenerationFailed)?;
        let oid = kem_type.get_oid();
        let pk = PublicKey::new(&oid, &pk)
            .map_err(|_| errors::QuantCryptError::KeyPairGenerationFailed)?;
        let sk = PrivateKey::new(&oid, &sk)
            .map_err(|_| errors::QuantCryptError::KeyPairGenerationFailed)?;
        Ok((pk, sk))
    }
}
