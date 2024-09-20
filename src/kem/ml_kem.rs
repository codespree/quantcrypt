use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use crate::kem::macros::encapsulate_ml;
use crate::kem::macros::key_gen_ml;
use ml_kem::kem::Decapsulate;
use ml_kem::kem::Encapsulate;
use ml_kem::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

// Get the encapsulated key object for the post quantum key encapsulation mechanism
///
/// # Arguments
///
/// * `pk` - The public key
///
/// # Returns
///
/// The encapsulated key object
fn get_encapsulation_key_obj<K: KemCore>(pk: Vec<u8>) -> Result<K::EncapsulationKey> {
    // Deserialize the public key
    let pk = Encoded::<K::EncapsulationKey>::try_from(pk.as_slice())?;
    Ok(K::EncapsulationKey::from_bytes(&pk))
}

/// Get the decapsulation key object for the post quantum key encapsulation mechanism
///
/// # Arguments
///
/// * `sk` - The secret key
///
/// # Returns
///
/// The decapsulation key object
fn get_decapsulation_key_obj<K: KemCore>(sk: &[u8]) -> Result<K::DecapsulationKey> {
    // Deserialize the public key
    let sk = Encoded::<K::DecapsulationKey>::try_from(sk)?;
    Ok(K::DecapsulationKey::from_bytes(&sk))
}

/// Decapsulate a ciphertext
///
/// # Arguments
///
/// * `sk` - The secret key to decapsulate with
/// * `ct` - The encapsulated key to decapsulate
///
/// # Returns
///
/// The shared secret (ss)
fn decapsulate<K: KemCore>(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let c = Ciphertext::<K>::try_from(ct)?;
    let dk = get_decapsulation_key_obj::<K>(sk)?;
    let session_key = dk.decapsulate(&c).unwrap();
    Ok(session_key.as_slice().to_vec())
}

/// A KEM manager for the MlKem method
pub struct MlKemManager {
    kem_type: KemType,
    rng: ChaCha20Rng,
}

impl Kem for MlKemManager {
    fn new(kem_type: KemType) -> Self {
        let rng = ChaCha20Rng::from_entropy();

        Self { kem_type, rng }
    }

    /// Generate a keypair
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
        // If seed is provided, use it to generate the keypair
        let mut rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(*seed)
        } else {
            self.rng.clone()
        };

        match self.kem_type {
            KemType::MlKem512 => Ok(key_gen_ml!(rng, MlKem512)),
            KemType::MlKem768 => Ok(key_gen_ml!(rng, MlKem768)),
            KemType::MlKem1024 => Ok(key_gen_ml!(rng, MlKem1024)),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the shares secret and ciphertext (ss, ct)
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.kem_type {
            KemType::MlKem512 => {
                encapsulate_ml!(self, MlKem512, pk)
            }
            KemType::MlKem768 => {
                encapsulate_ml!(self, MlKem768, pk)
            }
            KemType::MlKem1024 => {
                encapsulate_ml!(self, MlKem1024, pk)
            }
            _ => {
                panic!("Not implemented");
            }
        }
    }

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
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self.kem_type {
            KemType::MlKem512 => decapsulate::<MlKem512>(sk, ct),
            KemType::MlKem768 => decapsulate::<MlKem768>(sk, ct),
            KemType::MlKem1024 => decapsulate::<MlKem1024>(sk, ct),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    fn get_ss_byte_len(&self) -> usize {
        match self.kem_type {
            KemType::MlKem512 => 32,
            KemType::MlKem768 => 32,
            KemType::MlKem1024 => 32,
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Get the type of KEM
    ///
    /// # Returns
    ///
    /// The type of KEM
    fn get_kem_type(&self) -> KemType {
        self.kem_type.clone()
    }

    /// Get the length of the ciphertext in bytes
    /// (for the encaps method)
    ///
    /// # Returns
    ///
    /// The length of the ciphertext in bytes
    fn get_ct_byte_len(&self) -> Option<usize> {
        None
    }

    /// Get the length of the public key in bytes
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes
    fn get_pk_byte_len(&self) -> Option<usize> {
        match self.kem_type {
            KemType::MlKem512 => Some(800),
            KemType::MlKem768 => Some(1184),
            KemType::MlKem1024 => Some(1568),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Get the length of the secret key in bytes
    ///
    /// # Returns
    ///
    /// The length of the secret key in bytes
    fn get_sk_byte_len(&self) -> Option<usize> {
        match self.kem_type {
            KemType::MlKem512 => Some(1632),
            KemType::MlKem768 => Some(2400),
            KemType::MlKem1024 => Some(3168),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    fn get_oid(&self) -> String {
        match self.kem_type {
            KemType::MlKem512 => "2.16.840.1.101.3.4.4.1".to_string(),
            KemType::MlKem768 => "2.16.840.1.101.3.4.4.2".to_string(),
            KemType::MlKem1024 => "2.16.840.1.101.3.4.4.3".to_string(),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Not implemented
    fn get_pk(&self, _sk: &[u8]) -> Result<Vec<u8>> {
        panic!("Not implemented");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::kem_type::KemType;
    use crate::kem::macros::test_kem;

    #[test]
    fn test_ml_kem_512() {
        let mut kem = MlKemManager::new(KemType::MlKem512);
        test_kem!(kem);
    }

    #[test]
    fn test_ml_kem_768() {
        let mut kem = MlKemManager::new(KemType::MlKem768);
        test_kem!(kem);
    }

    #[test]
    fn test_ml_kem_1024() {
        let mut kem = MlKemManager::new(KemType::MlKem1024);
        test_kem!(kem);
    }
}
