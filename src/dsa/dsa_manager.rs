use std::error;

use rand_core::CryptoRngCore;

use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::dsa_type::DsaType;
use crate::dsa::composite_dsa::CompositeDsaManager;
use crate::dsa::ec_dsa::EcDsaManager;
use crate::dsa::ml_dsa::MlDsaManager;
use crate::dsa::rsa_dsa::RsaDsaManager;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

const ML_DSA_TYPES: [DsaType; 3] = [DsaType::MlDsa44, DsaType::MlDsa65, DsaType::MlDsa87];

const RSA_DSA_TYPES: [DsaType; 4] = [
    DsaType::Rsa2048Pkcs15SHA256,
    DsaType::Rsa2048PssSHA256,
    DsaType::Rsa3072Pkcs15SHA512,
    DsaType::Rsa3072PssSHA512,
];

const EC_DSA_TYPES: [DsaType; 8] = [
    DsaType::EcdsaP256SHA256,
    DsaType::EcdsaP256SHA512,
    DsaType::EcdsaP384SHA512,
    DsaType::EcdsaBrainpoolP256r1SHA512,
    DsaType::EcdsaBrainpoolP256r1SHA256,
    DsaType::EcdsaBrainpoolP384r1SHA512,
    DsaType::Ed25519SHA512,
    DsaType::Ed448SHA512,
];

const COMPOSITE_DSA_TYPES: [DsaType; 13] = [
    DsaType::MlDsa44Rsa2048PssSha256,
    DsaType::MlDsa44Rsa2048Pkcs15Sha256,
    DsaType::MlDsa44Ed25519SHA512,
    DsaType::MlDsa44EcdsaP256SHA256,
    DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256,
    DsaType::MlDsa65Rsa3072PssSHA512,
    DsaType::MlDsa65Rsa3072Pkcs15SHA512,
    DsaType::MlDsa65EcdsaP256SHA512,
    DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512,
    DsaType::MlDsa65Ed25519SHA512,
    DsaType::MlDsa87EcdsaP384SHA512,
    DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512,
    DsaType::MlDsa87Ed448SHA512,
];

/// Enum to representthe different types of KEM managers
pub enum DsaManager {
    /// ML DSA manager
    Ml(MlDsaManager),
    /// RSA DSA manager
    Rsa(RsaDsaManager),
    /// EC DSA manager
    Ec(EcDsaManager),
    /// Composite DSA manager
    Composite(CompositeDsaManager),
}

impl Dsa for DsaManager {
    fn new(dsa_type: DsaType) -> Self
    where
        Self: Sized,
    {
        match dsa_type {
            _ if ML_DSA_TYPES.contains(&dsa_type) => DsaManager::Ml(MlDsaManager::new(dsa_type)),
            _ if RSA_DSA_TYPES.contains(&dsa_type) => DsaManager::Rsa(RsaDsaManager::new(dsa_type)),
            _ if EC_DSA_TYPES.contains(&dsa_type) => DsaManager::Ec(EcDsaManager::new(dsa_type)),
            _ if COMPOSITE_DSA_TYPES.contains(&dsa_type) => {
                DsaManager::Composite(CompositeDsaManager::new(dsa_type))
            }
            _ => {
                panic!("Not implemented");
            }
        }
    }

    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            DsaManager::Ml(ml) => ml.key_gen(),
            DsaManager::Rsa(rsa) => rsa.key_gen(),
            DsaManager::Ec(ec) => ec.key_gen(),
            DsaManager::Composite(composite) => composite.key_gen(),
        }
    }

    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            DsaManager::Ml(ml) => ml.key_gen_with_rng(rng),
            DsaManager::Rsa(rsa) => rsa.key_gen_with_rng(rng),
            DsaManager::Ec(ec) => ec.key_gen_with_rng(rng),
            DsaManager::Composite(composite) => composite.key_gen_with_rng(rng),
        }
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            DsaManager::Ml(ml) => ml.sign(sk, msg),
            DsaManager::Rsa(rsa) => rsa.sign(sk, msg),
            DsaManager::Ec(ec) => ec.sign(sk, msg),
            DsaManager::Composite(composite) => composite.sign(sk, msg),
        }
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        match self {
            DsaManager::Ml(ml) => ml.verify(pk, msg, sig),
            DsaManager::Rsa(rsa) => rsa.verify(pk, msg, sig),
            DsaManager::Ec(ec) => ec.verify(pk, msg, sig),
            DsaManager::Composite(composite) => composite.verify(pk, msg, sig),
        }
    }

    fn get_dsa_info(&self) -> super::common::dsa_info::DsaInfo {
        match self {
            DsaManager::Ml(ml) => ml.get_dsa_info(),
            DsaManager::Rsa(rsa) => rsa.get_dsa_info(),
            DsaManager::Ec(ec) => ec.get_dsa_info(),
            DsaManager::Composite(composite) => composite.get_dsa_info(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::common::dsa_type::DsaType;

    #[test]
    fn test_dsa_manager() {
        let mut all_dsas: Vec<DsaType> = Vec::new();
        all_dsas.extend_from_slice(&ML_DSA_TYPES);
        all_dsas.extend_from_slice(&RSA_DSA_TYPES);
        all_dsas.extend_from_slice(&EC_DSA_TYPES);
        all_dsas.extend_from_slice(&COMPOSITE_DSA_TYPES);

        // This is just to test that the manager can create all DSA types
        for dsa_type in all_dsas {
            let dsa = DsaManager::new(dsa_type.clone());
            assert_eq!(dsa.get_dsa_info().dsa_type, dsa_type);
        }
    }
}
