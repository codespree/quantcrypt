use crate::kem::common::kem_info::KemInfo;
use crate::kem::common::kem_trait::Kem;
use crate::kem::common::kem_type::KemType;
use crate::QuantCryptError;
use ml_kem::kem::Decapsulate;
use ml_kem::kem::Encapsulate;
use ml_kem::*;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRngCore;
use rand_core::SeedableRng;

macro_rules! key_gen_ml {
    ($rng:expr, $curve:ident) => {{
        let (dk, ek) = $curve::generate($rng);
        (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
    }};
}

macro_rules! encapsulate_ml {
    ($rng:expr, $curve:ident, $pk:expr) => {{
        let ek = get_encapsulation_key_obj::<$curve>($pk.to_vec())?;
        let (ct, ss) = ek.encapsulate(&mut $rng).unwrap();
        let ct = ct.as_slice().to_vec();
        let ss = ss.as_slice().to_vec();
        Ok((ss, ct))
    }};
}

type Result<T> = std::result::Result<T, QuantCryptError>;

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
    let pk = Encoded::<K::EncapsulationKey>::try_from(pk.as_slice())
        .map_err(|_| QuantCryptError::InvalidPublicKey)?;
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
    let sk = Encoded::<K::DecapsulationKey>::try_from(sk)
        .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
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
    let c = Ciphertext::<K>::try_from(ct).map_err(|_| QuantCryptError::InvalidCiphertext)?;
    let dk = get_decapsulation_key_obj::<K>(sk)?;
    let session_key = dk
        .decapsulate(&c)
        .map_err(|_| QuantCryptError::DecapFailed)?;
    Ok(session_key.as_slice().to_vec())
}

/// A KEM manager for the MlKem method
pub struct MlKemManager {
    kem_info: KemInfo,
}

impl MlKemManager {
    pub fn key_gen_deterministic(&self, d: &B32, z: &B32) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.kem_info.kem_type {
            KemType::MlKem512 => {
                let result = MlKem512::generate_deterministic(d, z);
                Ok((result.1.as_bytes().to_vec(), result.0.as_bytes().to_vec()))
            }
            KemType::MlKem768 => {
                let result = MlKem768::generate_deterministic(d, z);
                Ok((result.1.as_bytes().to_vec(), result.0.as_bytes().to_vec()))
            }
            KemType::MlKem1024 => {
                let result = MlKem1024::generate_deterministic(d, z);
                Ok((result.1.as_bytes().to_vec(), result.0.as_bytes().to_vec()))
            }
            _ => Err(QuantCryptError::NotImplemented),
        }
    }
}

impl Kem for MlKemManager {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    ///
    /// # Returns
    ///
    /// A new KEM instance
    fn new(kem_type: KemType) -> Result<Self> {
        let kem_info = KemInfo::new(kem_type);
        Ok(Self { kem_info })
    }

    /// Generate a keypair
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.kem_info.kem_type {
            KemType::MlKem512 => Ok(key_gen_ml!(rng, MlKem512)),
            KemType::MlKem768 => Ok(key_gen_ml!(rng, MlKem768)),
            KemType::MlKem1024 => Ok(key_gen_ml!(rng, MlKem1024)),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Generate a keypair using the default RNG ChaCha20Rng
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = ChaCha20Rng::from_entropy();
        self.key_gen_with_rng(&mut rng)
    }

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the shared secret and ciphertext (ss, ct)
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = ChaCha20Rng::from_entropy();
        match self.kem_info.kem_type {
            KemType::MlKem512 => {
                encapsulate_ml!(rng, MlKem512, pk)
            }
            KemType::MlKem768 => {
                encapsulate_ml!(rng, MlKem768, pk)
            }
            KemType::MlKem1024 => {
                encapsulate_ml!(rng, MlKem1024, pk)
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
        match self.kem_info.kem_type {
            KemType::MlKem512 => decapsulate::<MlKem512>(sk, ct),
            KemType::MlKem768 => decapsulate::<MlKem768>(sk, ct),
            KemType::MlKem1024 => decapsulate::<MlKem1024>(sk, ct),
            _ => Err(QuantCryptError::NotImplemented),
        }
    }

    /// Get KEM metadata information such as the key lengths,
    /// size of ciphertext, etc.
    ///
    /// These values are also used to test the correctness of the KEM
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the KEM
    fn get_kem_info(&self) -> KemInfo {
        self.kem_info.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::common::kem_type::KemType;
    use crate::kem::common::macros::test_kem;

    #[test]
    fn test_ml_kem_512() {
        let kem = MlKemManager::new(KemType::MlKem512);
        test_kem!(kem);
    }

    #[test]
    fn test_ml_kem_768() {
        let kem = MlKemManager::new(KemType::MlKem768);
        test_kem!(kem);
    }

    #[test]
    fn test_ml_kem_1024() {
        let kem = MlKemManager::new(KemType::MlKem1024);
        test_kem!(kem);
    }
}
