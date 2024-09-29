use ed25519_dalek::SigningKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id;
use rand_core::CryptoRngCore;

use crate::dsa::common::dsa_info::DsaInfo;
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::dsa_type::DsaType;
use crate::utils::openssl_utils::sign_ec_based;
use crate::utils::openssl_utils::sign_pkey_based;
use crate::utils::openssl_utils::verify_ec_based;
use crate::utils::openssl_utils::verify_pkey_based;
use crate::utils::openssl_utils::{
    get_key_pair_ec_based, get_key_pair_ec_based_with_rng, get_key_pair_pkey_based,
};
use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Clone)]
pub struct EcDsaManager {
    pub dsa_info: DsaInfo,
    ec_based_nid: Option<Nid>,
    pk_based_id: Option<Id>,
    digest: MessageDigest,
}

impl Dsa for EcDsaManager {
    fn new(dsa_type: DsaType) -> Result<Self>
    where
        Self: Sized,
    {
        let dsa_info = DsaInfo::new(dsa_type.clone());
        let (ec_based_nid, pk_based_id, digest) = match dsa_type {
            DsaType::EcdsaP256SHA256 => {
                (Some(Nid::X9_62_PRIME256V1), None, MessageDigest::sha256())
            }
            DsaType::EcdsaP256SHA512 => {
                (Some(Nid::X9_62_PRIME256V1), None, MessageDigest::sha512())
            }
            DsaType::EcdsaP384SHA512 => (Some(Nid::SECP384R1), None, MessageDigest::sha512()),
            DsaType::EcdsaBrainpoolP256r1SHA256 => {
                (Some(Nid::BRAINPOOL_P256R1), None, MessageDigest::sha256())
            }
            DsaType::EcdsaBrainpoolP256r1SHA512 => {
                (Some(Nid::BRAINPOOL_P256R1), None, MessageDigest::sha512())
            }
            DsaType::EcdsaBrainpoolP384r1SHA512 => {
                (Some(Nid::BRAINPOOL_P384R1), None, MessageDigest::sha512())
            }
            DsaType::Ed25519SHA512 => (None, Some(Id::ED25519), MessageDigest::sha512()),
            DsaType::Ed448SHA512 => (None, Some(Id::ED448), MessageDigest::sha512()),
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };

        Ok(Self {
            dsa_info,
            ec_based_nid,
            pk_based_id,
            digest,
        })
    }

    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let result = if let Some(nid) = self.ec_based_nid {
            get_key_pair_ec_based(nid)
        } else if let Some(id) = self.pk_based_id {
            get_key_pair_pkey_based(id)
        } else {
            return Err(QuantCryptError::NotImplemented);
        };
        let result = result.map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
        Ok(result)
    }

    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        let result = if let Some(nid) = self.ec_based_nid {
            get_key_pair_ec_based_with_rng(rng, nid)
        } else if let Some(id) = self.pk_based_id {
            match id {
                Id::ED25519 => {
                    let sk = SigningKey::generate(rng);
                    let pk = sk.verifying_key().to_bytes();
                    let sk = sk.to_bytes();
                    Ok((pk.to_vec(), sk.to_vec()))
                }
                Id::ED448 => {
                    let sk = ed448_rust::PrivateKey::new(rng);
                    let pk = ed448_rust::PublicKey::from(&sk);
                    let pk = pk.as_byte();
                    let sk = sk.as_bytes();
                    Ok((pk.to_vec(), sk.to_vec()))
                }
                _ => {
                    return Err(QuantCryptError::NotImplemented);
                }
            }
        } else {
            return Err(QuantCryptError::NotImplemented);
        };
        let result = result.map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
        Ok(result)
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let result = if let Some(nid) = self.ec_based_nid {
            sign_ec_based(nid, sk, msg, self.digest)
        } else if let Some(id) = self.pk_based_id {
            sign_pkey_based(id, sk, msg)
        } else {
            return Err(QuantCryptError::NotImplemented);
        };
        let result = result.map_err(|_| QuantCryptError::SignatureFailed)?;
        Ok(result)
    }

    fn verify(&self, pk: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
        let result = if let Some(nid) = self.ec_based_nid {
            verify_ec_based(nid, pk, msg, signature, self.digest)
        } else if let Some(id) = self.pk_based_id {
            verify_pkey_based(id, pk, msg, signature)
        } else {
            return Err(QuantCryptError::NotImplemented);
        };
        let result = result.map_err(|_| QuantCryptError::SignatureVerificationFailed)?;
        Ok(result)
    }

    fn get_dsa_info(&self) -> DsaInfo {
        self.dsa_info.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::common::{dsa_type::DsaType, macros::test_dsa};

    #[test]
    fn test_ecdsa_p256_sha256() {
        let dsa = EcDsaManager::new(DsaType::EcdsaP256SHA256);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ecdsa_p256_sha512() {
        let dsa = EcDsaManager::new(DsaType::EcdsaP256SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ecdsa_p384_sha512() {
        let dsa = EcDsaManager::new(DsaType::EcdsaP384SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ecdsa_brainpool_p256r1_sha256() {
        let dsa = EcDsaManager::new(DsaType::EcdsaBrainpoolP256r1SHA256);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ecdsa_brainpool_p256r1_sha512() {
        let dsa = EcDsaManager::new(DsaType::EcdsaBrainpoolP256r1SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ecdsa_brainpool_p384r1_sha512() {
        let dsa = EcDsaManager::new(DsaType::EcdsaBrainpoolP384r1SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ed25519_sha512() {
        let dsa = EcDsaManager::new(DsaType::Ed25519SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ed448_sha512() {
        let dsa = EcDsaManager::new(DsaType::Ed448SHA512);
        test_dsa!(dsa);
    }
}
