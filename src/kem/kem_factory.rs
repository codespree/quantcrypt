use crate::kem::common::kem_trait::Kem;
use crate::kem::common::kem_type::KemType;
use crate::kem::composite_kem::CompositeKemManager;
use crate::kem::ec_kem::DhKemManager;
use crate::kem::ml_kem::MlKemManager;
use crate::kem::rsa_kem::RsaKemManager;

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

impl KemFactory {
    pub fn get_kem(kem_type: KemType) -> Box<dyn Kem> {
        match kem_type {
            _ if ML_KEM_TYPES.contains(&kem_type) => Box::new(MlKemManager::new(kem_type)),
            _ if RSA_KEM_TYPES.contains(&kem_type) => Box::new(RsaKemManager::new(kem_type)),
            _ if EC_KEM_TYPES.contains(&kem_type) => Box::new(DhKemManager::new(kem_type)),
            _ if COMPOSITE_KEM_TYPES.contains(&kem_type) => {
                Box::new(CompositeKemManager::new(kem_type))
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
