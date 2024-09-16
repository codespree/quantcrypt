use crate::kem::macros::{decapsulate_ecc, encapsulate_ecc, key_gen_ecc};

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
    fn new(kem_type: KemType) -> Self {
        let rng = ChaCha20Rng::from_entropy();
        Self { kem_type, rng }
    }

    /// Generate a keypair
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> (Vec<u8>, Vec<u8>) {
        // If seed is provided, use it to generate the keypair
        let mut rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(*seed)
        } else {
            self.rng.clone()
        };

        match self.kem_type {
            KemType::P256 => {
                key_gen_ecc!(rng, p256)
            }
            KemType::P384 => {
                key_gen_ecc!(rng, p384)
            }
            KemType::X25519 => {
                let sk = StaticSecret::random_from_rng(&mut rng);
                let pk = x25519_dalek::PublicKey::from(&sk);
                (pk.as_bytes().to_vec(), sk.to_bytes().to_vec())
            }
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
    /// A tuple containing the ciphertext and shared secret (ct, ss)
    fn encaps(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.kem_type {
            KemType::P256 => encapsulate_ecc!(p256, NistP256, pk, &mut self.rng),
            KemType::P384 => encapsulate_ecc!(p384, NistP384, pk, &mut self.rng),
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
            _ => {
                panic!("Not implemented");
            }
        }
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self.kem_type {
            KemType::P256 => {
                decapsulate_ecc!(p256, NistP256, sk, ct)
            }
            KemType::P384 => {
                decapsulate_ecc!(p384, NistP384, sk, ct)
            }
            KemType::X25519 => {
                let sk: [u8; 32] = sk.try_into()?;
                let sk = StaticSecret::from(sk);
                let pk: [u8; 32] = ct.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);
                let shared_secret = sk.diffie_hellman(&pk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            _ => {
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
    use crate::kem::macros::test_kem;

    #[test]
    fn test_ec_kem_p256() {
        let mut kem = DhKemManager::new(KemType::P256);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_p384() {
        let mut kem = DhKemManager::new(KemType::P384);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_x25519() {
        let mut kem = DhKemManager::new(KemType::X25519);
        test_kem!(kem);
    }
}
