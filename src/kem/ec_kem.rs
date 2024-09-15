use crate::kem::macros::{decapsulate, encapsulate, key_gen};

// use the macros to generate the encapsulate function

use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::AffinePoint;
use elliptic_curve::NonZeroScalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error;
use x25519_dalek::StaticSecret;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// A KEM manager for the DhKem method
pub struct DhKemManager {
    kem_type: KemType,
    rng: ChaCha20Rng,
}

impl Kem for DhKemManager {
    fn new(kem_type: KemType, seed: Option<[u8; 32]>) -> Self {
        let rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(seed)
        } else {
            ChaCha20Rng::from_entropy()
        };
        Self { kem_type, rng }
    }

    /// Generate a keypair
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self) -> (Vec<u8>, Vec<u8>) {
        match self.kem_type {
            KemType::P256 => {
                key_gen!(self, p256)
            }
            KemType::P384 => {
                key_gen!(self, p384)
            }
            KemType::X25519 => {
                let sk = StaticSecret::random_from_rng(&mut self.rng);
                let pk = x25519_dalek::PublicKey::from(&sk);
                (pk.as_bytes().to_vec(), sk.to_bytes().to_vec())
            }
            KemType::MlKem768 => {
                panic!("Not implemented");
            }
            KemType::MlKem1024 => {
                panic!("Not implemented");
            }
            KemType::MlKem512 => {
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
    /// A tuple containing the ciphertext and shared secret (ct, ss)
    fn encaps(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.kem_type {
            KemType::P256 => encapsulate!(p256, NistP256, pk, &mut self.rng),
            KemType::P384 => encapsulate!(p384, NistP384, pk, &mut self.rng),
            KemType::X25519 => {
                // Cast public key to 32 bytes
                let pk: [u8; 32] = pk.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);

                let sk = StaticSecret::random_from_rng(&mut self.rng);
                let shared_secret = sk.diffie_hellman(&pk);

                // Get the public key from the ephemeral secret
                let ct = x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec();
                Ok((ct, shared_secret.as_bytes().to_vec()))
            }
            KemType::MlKem768 => {
                panic!("Not implemented");
            }
            KemType::MlKem1024 => {
                panic!("Not implemented");
            }
            KemType::MlKem512 => {
                panic!("Not implemented");
            }
        }
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self.kem_type {
            KemType::P256 => {
                decapsulate!(p256, NistP256, sk, ct)
            }
            KemType::P384 => {
                decapsulate!(p384, NistP384, sk, ct)
            }
            KemType::X25519 => {
                let sk: [u8; 32] = sk.try_into()?;
                let sk = StaticSecret::from(sk);
                let pk: [u8; 32] = ct.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);
                let shared_secret = sk.diffie_hellman(&pk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemType::MlKem768 => {
                panic!("Not implemented");
            }
            KemType::MlKem1024 => {
                panic!("Not implemented");
            }
            KemType::MlKem512 => {
                panic!("Not implemented");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::kem_trait::Kem;
    use crate::kem::kem_type::KemType;

    #[test]
    fn test_ec_kem_p256() {
        let mut kem = DhKemManager::new(KemType::P256, None);
        let (pk, sk) = kem.key_gen();
        let (ct, ss) = kem.encaps(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_ec_kem_p384() {
        let mut kem = DhKemManager::new(KemType::P384, None);
        let (pk, sk) = kem.key_gen();
        let (ct, ss) = kem.encaps(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_ec_kem_x25519() {
        let mut kem = DhKemManager::new(KemType::X25519, None);
        let (pk, sk) = kem.key_gen();
        let (ct, ss) = kem.encaps(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);
    }
}
