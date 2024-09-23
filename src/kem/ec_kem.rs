// use the macros to generate the encapsulate functio
use crate::kem::common::kem_info::KemInfo;
use crate::kem::common::kem_trait::Kem;
use crate::kem::common::kem_type::KemType;
use crate::utils::openssl_utils::{
    decaps_ec_based, decaps_pkey_based, encaps_ec_based, encaps_pkey_based, get_key_pair_ec_based,
    get_key_pair_ec_based_with_rng, get_key_pair_pkey_based, get_keypair_pkey_based_with_rng,
};
use openssl::nid::Nid;
use openssl::pkey::Id;
use rand_core::CryptoRngCore;
use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// A KEM manager for the DhKem method
pub struct EcKemManager {
    kem_info: KemInfo,
    ec_based_nid: Option<Nid>,
    pk_based_id: Option<Id>,
}

impl Kem for EcKemManager {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    fn new(kem_type: KemType) -> Self {
        let kem_info = KemInfo::new(kem_type.clone());
        let (ec_based_nid, pk_based_id) = match kem_type {
            KemType::P256 => (Some(Nid::X9_62_PRIME256V1), None),
            KemType::P384 => (Some(Nid::SECP384R1), None),
            KemType::BrainpoolP256r1 => (Some(Nid::BRAINPOOL_P256R1), None),
            KemType::BrainpoolP384r1 => (Some(Nid::BRAINPOOL_P384R1), None),
            KemType::X25519 => (None, Some(Id::X25519)),
            KemType::X448 => (None, Some(Id::X448)),
            _ => {
                panic!("Not implemented");
            }
        };
        Self {
            kem_info,
            ec_based_nid,
            pk_based_id,
        }
    }

    /// Generate a keypair using the default RNG of OpenSSL
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk).
    ///
    /// pk, sk, ct, lengths are all in accordance with RFC9180.
    /// ss length is different from RFC9180 as it is not hashed.
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        if let Some(nid) = self.ec_based_nid {
            get_key_pair_ec_based(nid)
        } else if let Some(id) = self.pk_based_id {
            get_key_pair_pkey_based(id)
        } else {
            panic!("Not implemented");
        }
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
    ///
    /// pk, sk, ct, lengths are all in accordance with RFC9180.
    /// ss length is different from RFC9180 as it is not hashed.
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        if let Some(nid) = self.ec_based_nid {
            get_key_pair_ec_based_with_rng(rng, nid)
        } else if let Some(id) = self.pk_based_id {
            get_keypair_pkey_based_with_rng(rng, id)
        } else {
            panic!("Not implemented");
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
        if let Some(nid) = self.ec_based_nid {
            encaps_ec_based(pk, nid)
        } else if let Some(id) = self.pk_based_id {
            encaps_pkey_based(pk, id)
        } else {
            panic!("Not implemented");
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
        if let Some(nid) = self.ec_based_nid {
            decaps_ec_based(sk, ct, nid)
        } else if let Some(id) = self.pk_based_id {
            decaps_pkey_based(sk, ct, id)
        } else {
            panic!("Not implemented");
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
    use crate::kem::common::kem_trait::Kem;
    use crate::kem::common::kem_type::KemType;
    use crate::kem::common::macros::test_kem;

    #[test]
    fn test_ec_kem_p256() {
        let mut kem = EcKemManager::new(KemType::P256);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_p384() {
        let mut kem = EcKemManager::new(KemType::P384);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_brainpool_p256r1() {
        let mut kem = EcKemManager::new(KemType::BrainpoolP256r1);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_brainpool_p384r1() {
        let mut kem = EcKemManager::new(KemType::BrainpoolP384r1);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_x448() {
        let mut kem = EcKemManager::new(KemType::X448);
        test_kem!(kem);
    }

    #[test]
    fn test_ec_kem_x25519() {
        let mut kem = EcKemManager::new(KemType::X25519);
        test_kem!(kem);
    }
}
