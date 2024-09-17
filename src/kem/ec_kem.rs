// use the macros to generate the encapsulate functio
use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use crate::kem::openssl_deterministic::{decaps_ossl, encaps_ossl, get_key_pair_ossl};
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error;
use x25519_dalek::StaticSecret;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// A KEM manager for the DhKem method
pub struct DhKemManager {
    kem_type: KemType,
}

impl Kem for DhKemManager {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    fn new(kem_type: KemType) -> Self {
        Self { kem_type }
    }

    /// Generate a keypair
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
        //TODO: Ensure that serialization is correct
        // If seed is provided, use it to generate the keypair
        let rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(*seed)
        } else {
            ChaCha20Rng::from_entropy()
        };

        match self.kem_type {
            KemType::P256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
                Ok(get_key_pair_ossl(seed, &group)?)
            }
            KemType::P384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
                Ok(get_key_pair_ossl(seed, &group)?)
            }
            KemType::X25519 => {
                //TODO: Check clamping
                /*
                *  For X25519 and X448, private keys are identical to their byte string
                   representation, so little processing has to be done.  The
                   SerializePrivateKey() function MUST clamp its output and the
                   DeserializePrivateKey() function MUST clamp its input, where
                   _clamping_ refers to the bitwise operations performed on k in the
                   decodeScalar25519() and decodeScalar448() functions defined in
                   Section 5 of [RFC7748].
                */
                let sk = StaticSecret::random_from_rng(rng);
                let pk = x25519_dalek::PublicKey::from(&sk);
                Ok((pk.as_bytes().to_vec(), sk.to_bytes().to_vec()))
            }
            KemType::BrainpoolP256r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P256R1).unwrap();
                Ok(get_key_pair_ossl(seed, &group)?)
            }
            KemType::BrainpoolP384r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1).unwrap();
                Ok(get_key_pair_ossl(seed, &group)?)
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
        let rng = ChaCha20Rng::from_entropy();
        match self.kem_type {
            KemType::P256 => encaps_ossl(pk, &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?),
            KemType::P384 => encaps_ossl(pk, &EcGroup::from_curve_name(Nid::SECP384R1)?),
            KemType::X25519 => {
                // Cast public key to 32 bytes
                let pk: [u8; 32] = pk.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);

                let sk = StaticSecret::random_from_rng(rng);
                let shared_secret = sk.diffie_hellman(&pk);

                // Get the public key from the ephemeral secret
                let ct = x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec();
                Ok((ct, shared_secret.as_bytes().to_vec()))
            }
            KemType::BrainpoolP256r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P256R1).unwrap();
                encaps_ossl(pk, &group)
            }
            KemType::BrainpoolP384r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1).unwrap();
                encaps_ossl(pk, &group)
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
    /// The shared secret (ss)
    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self.kem_type {
            KemType::P256 => decaps_ossl(sk, ct),
            KemType::P384 => decaps_ossl(sk, ct),
            KemType::X25519 => {
                let sk: [u8; 32] = sk.try_into()?;
                let sk = StaticSecret::from(sk);
                let pk: [u8; 32] = ct.try_into()?;
                let pk = x25519_dalek::PublicKey::from(pk);
                let shared_secret = sk.diffie_hellman(&pk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemType::BrainpoolP256r1 => decaps_ossl(sk, ct),
            KemType::BrainpoolP384r1 => decaps_ossl(sk, ct),
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
        let (pk, sk) = kem.key_gen(None).unwrap();
        // Assert the expected length
        assert_eq!(pk.len(), 32);
        assert_eq!(sk.len(), 32);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_brainpool_p256r1() {
        let mut kem = DhKemManager::new(KemType::BrainpoolP256r1);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_brainpool_p384r1() {
        let mut kem = DhKemManager::new(KemType::BrainpoolP384r1);
        test_kem!(kem);
    }
}
