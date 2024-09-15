use crate::kem::macros::{decapsulate, encapsulate, key_gen};

// use the macros to generate the encapsulate function

use crate::kem::kem_trait::Kem;
use crate::kem::ec_kem_type::EcKemType;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore, CryptoRng};
use std::error;
use elliptic_curve::AffinePoint;
use elliptic_curve::NonZeroScalar;
use x25519_dalek::StaticSecret;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// A KEM manager for the DhKem method
pub struct DhKemManager {
    kem_type: EcKemType,
    rng: ChaCha20Rng,
}

impl Kem for DhKemManager {
    fn new(kem_type: EcKemType, seed: Option<[u8; 32]>) -> Self {
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
            EcKemType::P256 => {
                key_gen!(self, p256)
            }
            EcKemType::P384 => {
                key_gen!(self, p384)
            },
            EcKemType::X25519 => {
                let sk = StaticSecret::random_from_rng(&mut self.rng);
                let pk = x25519_dalek::PublicKey::from(&sk);
                (pk.as_bytes().to_vec(), sk.to_bytes().to_vec())
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
            EcKemType::P256 => encapsulate!(p256, NistP256, pk, &mut self.rng),
            EcKemType::P384 => encapsulate!(p384, NistP384, pk, &mut self.rng),
            EcKemType::X25519 => {
                // Cast public key to 32 bytes
                let pk:[u8; 32] = pk.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);
                
                let sk = StaticSecret::random_from_rng(&mut self.rng);
                let shared_secret = sk.diffie_hellman(&pk);

                // Get the public key from the ephemeral secret
                let ct = x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec();
                Ok((ct, shared_secret.as_bytes().to_vec()))
            }
        }
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self.kem_type {
            EcKemType::P256 => {
                decapsulate!(p256, NistP256, sk, ct)
            }
            EcKemType::P384 => {
                decapsulate!(p384, NistP384, sk, ct)
            },
            EcKemType::X25519 => {
                let sk: [u8;32] = sk.try_into()?;
                let sk = StaticSecret::from(sk);
                let pk: [u8;32] = ct.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);
                let shared_secret = sk.diffie_hellman(&pk);
                Ok(shared_secret.as_bytes().to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::kem_trait::Kem;
    use crate::kem::ec_kem_type::EcKemType;

    #[test]
    fn test_dh_kem_p256() {
        let mut kem = DhKemManager::new(EcKemType::P256, None);
        let (pk, sk) = kem.key_gen();
        let (ct, ss) = kem.encaps(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_dh_kem_p384() {
        let mut kem = DhKemManager::new(EcKemType::P384, None);
        let (pk, sk) = kem.key_gen();
        let (ct, ss) = kem.encaps(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_dh_kem_x25519() {
        let mut kem = DhKemManager::new(EcKemType::X25519, None);
        let (pk, sk) = kem.key_gen();
        let (ct, ss) = kem.encaps(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);
    }
}
