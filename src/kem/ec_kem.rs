// use the macros to generate the encapsulate functio
use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use crate::kem::openssl_utils::{
    decaps_ec_based, decaps_pkey_based_ossl, encaps_ec_based, encaps_pkey_based,
    get_key_pair_ec_based, get_keypair_pkey_based,
};
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use openssl::pkey::Id;
use std::error;

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
        match self.kem_type {
            KemType::P256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                Ok(get_key_pair_ec_based(seed, &group)?)
            }
            KemType::P384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                Ok(get_key_pair_ec_based(seed, &group)?)
            }
            KemType::X25519 => get_keypair_pkey_based(seed, Id::X25519),
            KemType::BrainpoolP256r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P256R1)?;
                Ok(get_key_pair_ec_based(seed, &group)?)
            }
            KemType::BrainpoolP384r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)?;
                Ok(get_key_pair_ec_based(seed, &group)?)
            }
            KemType::X448 => get_keypair_pkey_based(seed, Id::X448),
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
    /// A tuple containing the shared secret and ciphertext (ss, ct)
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.kem_type {
            KemType::P256 => encaps_ec_based(pk, &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?),
            KemType::P384 => encaps_ec_based(pk, &EcGroup::from_curve_name(Nid::SECP384R1)?),
            KemType::X25519 => encaps_pkey_based(pk, Id::X25519),
            KemType::BrainpoolP256r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P256R1)?;
                encaps_ec_based(pk, &group)
            }
            KemType::BrainpoolP384r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)?;
                encaps_ec_based(pk, &group)
            }
            KemType::X448 => encaps_pkey_based(pk, Id::X448),
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
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self.kem_type {
            KemType::P256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                decaps_ec_based(sk, ct, &group)
            }
            KemType::P384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                decaps_ec_based(sk, ct, &group)
            }
            KemType::X25519 => decaps_pkey_based_ossl(sk, ct, Id::X25519),
            KemType::BrainpoolP256r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P256R1)?;
                decaps_ec_based(sk, ct, &group)
            }
            KemType::BrainpoolP384r1 => {
                let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)?;
                decaps_ec_based(sk, ct, &group)
            }
            KemType::X448 => decaps_pkey_based_ossl(sk, ct, Id::X448),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Get the length of the shared secret in bytes
    ///
    /// # Returns
    ///
    /// The length of the shared secret in bytes
    fn get_ss_byte_len(&self) -> usize {
        match self.kem_type {
            KemType::P256 => 32,
            KemType::P384 => 48,
            KemType::X25519 => 32,
            KemType::BrainpoolP256r1 => 32,
            KemType::BrainpoolP384r1 => 48,
            KemType::X448 => 56,
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
        self.get_pk_byte_len()
    }

    /// Get the length of the public key in bytes
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes
    fn get_pk_byte_len(&self) -> Option<usize> {
        match self.kem_type {
            KemType::P256 => Some(65),
            KemType::P384 => Some(97),
            KemType::X25519 => Some(32),
            KemType::BrainpoolP256r1 => Some(65),
            KemType::BrainpoolP384r1 => Some(97),
            KemType::X448 => Some(56),
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
            KemType::P256 => Some(32),
            KemType::P384 => Some(48),
            KemType::X25519 => Some(32),
            KemType::BrainpoolP256r1 => Some(32),
            KemType::BrainpoolP384r1 => Some(48),
            KemType::X448 => Some(56),
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
    fn test_ec_kem_brainpool_p256r1() {
        let mut kem = DhKemManager::new(KemType::BrainpoolP256r1);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_brainpool_p384r1() {
        let mut kem = DhKemManager::new(KemType::BrainpoolP384r1);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_x448() {
        let mut kem = DhKemManager::new(KemType::X448);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_x25519() {
        let mut kem = DhKemManager::new(KemType::X25519);
        test_kem!(kem);
    }
}
