use rand_core::CryptoRngCore;

use crate::kem::common::kem_info::KemInfo;
use crate::kem::common::kem_trait::Kem;
use crate::kem::common::kem_type::KemType;
use crate::kem::composite_kem::CompositeKemManager;
use crate::kem::ec_kem::DhKemManager;
use crate::kem::ml_kem::MlKemManager;
use crate::kem::rsa_kem::RsaKemManager;

use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub struct KemFactory {}

const ML_KEM_TYPES: [KemType; 3] = [KemType::MlKem512, KemType::MlKem768, KemType::MlKem1024];

const RSA_KEM_TYPES: [KemType; 3] = [
    KemType::RsaOAEP2048,
    KemType::RsaOAEP3072,
    KemType::RsaOAEP4096,
];

const EC_KEM_TYPES: [KemType; 6] = [
    KemType::P256,
    KemType::P384,
    KemType::X25519,
    KemType::BrainpoolP256r1,
    KemType::BrainpoolP384r1,
    KemType::X448,
];

const COMPOSITE_KEM_TYPES: [KemType; 9] = [
    KemType::MlKem768Rsa2048,
    KemType::MlKem768Rsa3072,
    KemType::MlKem768Rsa4096,
    KemType::MlKem768X25519,
    KemType::MlKem768P384,
    KemType::MlKem768BrainpoolP256r1,
    KemType::MlKem1024P384,
    KemType::MlKem1024BrainpoolP384r1,
    KemType::MlKem1024X448,
];

/// Enum to representthe different types of KEM managers
pub enum KemManager {
    /// ML KEM manager
    Ml(MlKemManager),
    /// RSA KEM manager
    Rsa(RsaKemManager),
    /// EC KEM manager
    Dh(DhKemManager),
    /// Composite KEM manager
    Composite(CompositeKemManager),
}

impl Kem for KemManager {
    /// Create a new KEM manager
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    ///
    /// # Returns
    ///
    /// A new KEM manager
    fn new(kem_type: KemType) -> Self
    where
        Self: Sized,
    {
        match kem_type {
            _ if ML_KEM_TYPES.contains(&kem_type) => KemManager::Ml(MlKemManager::new(kem_type)),
            _ if RSA_KEM_TYPES.contains(&kem_type) => KemManager::Rsa(RsaKemManager::new(kem_type)),
            _ if EC_KEM_TYPES.contains(&kem_type) => KemManager::Dh(DhKemManager::new(kem_type)),
            _ if COMPOSITE_KEM_TYPES.contains(&kem_type) => {
                KemManager::Composite(CompositeKemManager::new(kem_type))
            }
            _ => {
                panic!("Not implemented");
            }
        }
    }

    //// Get the KEM info for the KEM manager. This represents
    /// the KEM type and the length of various parameters
    ///
    /// # Returns
    ///
    /// The KEM info for the KEM manager
    fn get_kem_info(&self) -> KemInfo {
        match self {
            KemManager::Ml(kem) => kem.get_kem_info(),
            KemManager::Rsa(kem) => kem.get_kem_info(),
            KemManager::Dh(kem) => kem.get_kem_info(),
            KemManager::Composite(kem) => kem.get_kem_info(),
        }
    }

    /// Generate a keypair using a specified RNG
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            KemManager::Ml(kem) => kem.key_gen_with_rng(rng),
            KemManager::Rsa(kem) => kem.key_gen_with_rng(rng),
            KemManager::Dh(kem) => kem.key_gen_with_rng(rng),
            KemManager::Composite(kem) => kem.key_gen_with_rng(rng),
        }
    }

    /// Generate a keypair using the default RNG. For OpenSSL, this is the default RNG,
    /// for RSA and ML KEMs, this is the ChaCha20 RNG
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            KemManager::Ml(kem) => kem.key_gen(),
            KemManager::Rsa(kem) => kem.key_gen(),
            KemManager::Dh(kem) => kem.key_gen(),
            KemManager::Composite(kem) => kem.key_gen(),
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
        match self {
            KemManager::Ml(kem) => kem.encap(pk),
            KemManager::Rsa(kem) => kem.encap(pk),
            KemManager::Dh(kem) => kem.encap(pk),
            KemManager::Composite(kem) => kem.encap(pk),
        }
    }

    /// Decapsulate a ciphertext
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext to decapsulate
    /// * `sk` - The secret key to decapsulate with
    ///
    /// # Returns
    ///
    /// The shared secret (ss)
    fn decap(&self, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
        match self {
            KemManager::Ml(kem) => kem.decap(ct, sk),
            KemManager::Rsa(kem) => kem.decap(ct, sk),
            KemManager::Dh(kem) => kem.decap(ct, sk),
            KemManager::Composite(kem) => kem.decap(ct, sk),
        }
    }
}

impl KemFactory {
    pub fn get_kem(kem_type: KemType) -> KemManager {
        match kem_type {
            _ if ML_KEM_TYPES.contains(&kem_type) => KemManager::Ml(MlKemManager::new(kem_type)),
            _ if RSA_KEM_TYPES.contains(&kem_type) => KemManager::Rsa(RsaKemManager::new(kem_type)),
            _ if EC_KEM_TYPES.contains(&kem_type) => KemManager::Dh(DhKemManager::new(kem_type)),
            _ if COMPOSITE_KEM_TYPES.contains(&kem_type) => {
                KemManager::Composite(CompositeKemManager::new(kem_type))
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
    use crate::kem::common::kem_type::KemType;

    #[test]
    fn test_kem_factory() {
        let mut all_kems: Vec<KemType> = Vec::new();
        all_kems.extend_from_slice(&ML_KEM_TYPES);
        all_kems.extend_from_slice(&RSA_KEM_TYPES);
        all_kems.extend_from_slice(&EC_KEM_TYPES);
        all_kems.extend_from_slice(&COMPOSITE_KEM_TYPES);

        // This is just to test that the factory can create all KEM types
        for kem_type in all_kems {
            let kem = KemFactory::get_kem(kem_type.clone());
            assert_eq!(kem.get_kem_info().kem_type, kem_type);
        }
    }
}
