use rand_core::CryptoRngCore;

use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::prehash_dsa_trait::PrehashDsa;
use crate::dsa::common::dsa_type::DsaType;
use crate::dsa::common::prehash_dsa_type::PrehashDsaType;
use crate::dsa::composite_dsa::CompositeDsaManager;
use crate::dsa::ec_dsa::EcDsaManager;
use crate::dsa::ml_dsa::MlDsaManager;
use crate::dsa::rsa_dsa::RsaDsaManager;
use crate::QuantCryptError;

use crate::dsa::slh_dsa::SlhDsaManager;

type Result<T> = std::result::Result<T, QuantCryptError>;

const ML_DSA_TYPES: [PrehashDsaType; 3] = [PrehashDsaType::MlDsa44, PrehashDsaType::MlDsa65, PrehashDsaType::MlDsa87];

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

// TODO: Uncomment the new types and implement their logic
// This includes 
const COMPOSITE_DSA_TYPES: [PrehashDsaType; 11] = [
    PrehashDsaType::MlDsa44Rsa2048Pss,
    PrehashDsaType::MlDsa44Rsa2048Pkcs15,
    PrehashDsaType::MlDsa44Ed25519,
    PrehashDsaType::MlDsa44EcdsaP256,
    PrehashDsaType::MlDsa65Rsa3072Pss,
    PrehashDsaType::MlDsa65Rsa3072Pkcs15,
    //PrehashDsaType::MlDsa65EcdsaP384,
    PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1,
    PrehashDsaType::MlDsa65Ed25519,
    PrehashDsaType::MlDsa87EcdsaP384,
    PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1,
    PrehashDsaType::MlDsa87Ed448,
    //PrehashDsaType::MlDsa65Rsa4096Pss, 
    //PrehashDsaType::MlDsa65Rsa4096Pkcs15,
];

const SLH_DSA_TYPES: [DsaType; 12] = [
    DsaType::SlhDsaSha2_128s,
    DsaType::SlhDsaSha2_128f,
    DsaType::SlhDsaSha2_192s,
    DsaType::SlhDsaSha2_192f,
    DsaType::SlhDsaSha2_256s,
    DsaType::SlhDsaSha2_256f,
    DsaType::SlhDsaShake128s,
    DsaType::SlhDsaShake128f,
    DsaType::SlhDsaShake192s,
    DsaType::SlhDsaShake192f,
    DsaType::SlhDsaShake256s,
    DsaType::SlhDsaShake256f,
];

// Implement clone
#[derive(Clone)]
/// Enum to representthe different types of KEM managers
pub enum DsaManager {
    /// RSA DSA manager
    Rsa(RsaDsaManager),
    /// EC DSA manager
    Ec(EcDsaManager),
    /// SLH DSA manager
    Slh(SlhDsaManager),
}

// Implement clone
#[derive(Clone)]
/// Enum to representthe different types of KEM managers
pub enum PrehashDsaManager {
    /// ML DSA manager
    Ml(MlDsaManager),
    /// Composite DSA manager
    Composite(CompositeDsaManager),
}

impl Dsa for DsaManager {
    fn new(dsa_type: DsaType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match dsa_type {
            _ if RSA_DSA_TYPES.contains(&dsa_type) => {
                DsaManager::Rsa(RsaDsaManager::new(dsa_type)?)
            }
            _ if SLH_DSA_TYPES.contains(&dsa_type) => {
                DsaManager::Slh(SlhDsaManager::new(dsa_type)?)
            }
            _ if EC_DSA_TYPES.contains(&dsa_type) => DsaManager::Ec(EcDsaManager::new(dsa_type)?),
            _ => {
                panic!("Not implemented");
            }
        };
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            DsaManager::Rsa(rsa) => rsa.key_gen(),
            DsaManager::Ec(ec) => ec.key_gen(),
            DsaManager::Slh(slh) => slh.key_gen(),
        }
    }

    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            DsaManager::Rsa(rsa) => rsa.key_gen_with_rng(rng),
            DsaManager::Ec(ec) => ec.key_gen_with_rng(rng),
            DsaManager::Slh(slh) => slh.key_gen_with_rng(rng),
        }
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            DsaManager::Rsa(rsa) => rsa.sign(sk, msg),
            DsaManager::Ec(ec) => ec.sign(sk, msg),
            DsaManager::Slh(slh) => slh.sign(sk, msg),
        }
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        match self {
            DsaManager::Rsa(rsa) => rsa.verify(pk, msg, sig),
            DsaManager::Ec(ec) => ec.verify(pk, msg, sig),
            DsaManager::Slh(slh) => slh.verify(pk, msg, sig),
        }
    }

    fn get_dsa_info(&self) -> super::common::dsa_info::DsaInfo {
        match self {
            DsaManager::Rsa(rsa) => rsa.get_dsa_info(),
            DsaManager::Ec(ec) => ec.get_dsa_info(),
            DsaManager::Slh(slh) => slh.get_dsa_info(),
        }
    }

    fn get_public_key(&self, sk: &[u8]) -> Result<Vec<u8>> {
        match self {
            DsaManager::Rsa(rsa) => rsa.get_public_key(sk),
            DsaManager::Ec(ec) => ec.get_public_key(sk),
            DsaManager::Slh(slh) => slh.get_public_key(sk),
        }
    }
}

impl PrehashDsa for PrehashDsaManager {
    fn new(dsa_type: PrehashDsaType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match dsa_type {
            _ if ML_DSA_TYPES.contains(&dsa_type) => PrehashDsaManager::Ml(MlDsaManager::new(dsa_type)?),
            _ if COMPOSITE_DSA_TYPES.contains(&dsa_type) => {
                PrehashDsaManager::Composite(CompositeDsaManager::new(dsa_type)?)
            }
            _ => {
                panic!("Not implemented");
            }
        };
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.key_gen(),
            PrehashDsaManager::Composite(composite) => composite.key_gen(),
        }
    }

    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.key_gen_with_rng(rng),
            PrehashDsaManager::Composite(composite) => composite.key_gen_with_rng(rng),
        }
    }

    fn sign(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.sign(sk, msg, ctx),
            PrehashDsaManager::Composite(composite) => composite.sign(sk, msg, ctx),
        }
    }

    fn sign_prehash(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>, ph: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.sign_prehash(sk, msg, ctx, ph),
            PrehashDsaManager::Composite(composite) => composite.sign_prehash(sk, msg, ctx, ph),
        }
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> Result<bool> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.verify(pk, msg, sig, ctx),
            PrehashDsaManager::Composite(composite) => composite.verify(pk, msg, sig, ctx),
        }
    }

    fn verify_prehash(&self, pk: &[u8], msg: &[u8], sig: &[u8], ctx: Option<&[u8]>, ph: &[u8]) -> Result<bool> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.verify(pk, msg, sig, ctx),
            PrehashDsaManager::Composite(composite) => composite.verify_prehash(pk, msg, sig, ctx, ph),
        }
    }

    fn get_dsa_info(&self) -> super::common::prehash_dsa_info::PrehashDsaInfo {
        match self {
            PrehashDsaManager::Ml(ml) => ml.get_dsa_info(),
            PrehashDsaManager::Composite(composite) => composite.get_dsa_info(),
        }
    }

    fn get_public_key(&self, sk: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrehashDsaManager::Ml(ml) => ml.get_public_key(sk),
            PrehashDsaManager::Composite(composite) => composite.get_public_key(sk),
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
        all_dsas.extend_from_slice(&RSA_DSA_TYPES);
        all_dsas.extend_from_slice(&EC_DSA_TYPES);
        all_dsas.extend_from_slice(&SLH_DSA_TYPES);

        // This is just to test that the manager can create all DSA types
        for dsa_type in all_dsas {
            let dsa = DsaManager::new(dsa_type.clone()).unwrap();
            assert_eq!(dsa.get_dsa_info().dsa_type, dsa_type);
        }
    }

    #[test]
    fn test_prehash_dsa_manager() {
        let mut all_dsas: Vec<PrehashDsaType> = Vec::new();
        all_dsas.extend_from_slice(&ML_DSA_TYPES);
        all_dsas.extend_from_slice(&COMPOSITE_DSA_TYPES);

        // This is just to test that the manager can create all DSA types
        for dsa_type in all_dsas {
            let dsa = PrehashDsaManager::new(dsa_type.clone()).unwrap();
            assert_eq!(dsa.get_dsa_info().dsa_type, dsa_type);
        }
    }
}

