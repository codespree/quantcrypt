use crate::asn1::asn_util::oid_to_der;
use crate::asn1::composite_private_key::CompositePrivateKey;
use crate::asn1::composite_public_key::CompositePublicKey;
use crate::dsa::asn1::composite_dsa_primitives::CompositeSignatureValue;
use crate::dsa::common::dsa_info::DsaInfo;
use crate::dsa::dsa_manager::DsaManager;
use crate::QuantCryptError;
use openssl::hash::Hasher;
use openssl::hash::MessageDigest;

use der::{Decode, Encode};
use pkcs8::ObjectIdentifier;
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};

use super::common::{dsa_trait::Dsa, dsa_type::DsaType};

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A DSA manager for the composite KEM method
#[derive(Clone)]
pub struct CompositeDsaManager {
    /// The KEM metadata information
    dsa_info: DsaInfo,
    /// The traditional DSA manager
    trad_dsa: Box<DsaManager>,
    /// The post-quantum DSA manager
    pq_dsa: Box<DsaManager>,
    /// The key derivation function
    kdf: MessageDigest,
}

impl CompositeDsaManager {
    /// Get's the prehash message for the composite DSA
    ///
    /// # Arguments
    ///
    /// * `msg` - the message to pre-hash
    ///
    /// # Returns
    ///
    /// The pre-hashed message
    fn pre_hash(&self, msg: &[u8]) -> Result<Vec<u8>> {
        // Pre hash the message
        let mut hasher = Hasher::new(self.kdf).map_err(|_| QuantCryptError::SignatureFailed)?;
        hasher
            .update(msg)
            .map_err(|_| QuantCryptError::SignatureFailed)?;
        let msg = hasher
            .finish()
            .map_err(|_| QuantCryptError::SignatureFailed)?;

        let mut domain = oid_to_der(&self.dsa_info.oid)?;
        domain.extend_from_slice(&msg);

        let msg = domain;
        Ok(msg)
    }

    /// Generate a composite DSA keypair from constituent keys
    ///
    /// # Arguments
    ///
    /// * `t_pk` - The traditional public key
    /// * `t_sk` - The traditional secret key
    /// * `pq_pk` - The post-quantum public key
    /// * `pq_sk` - The post-quantum secret key
    ///
    /// # Returns
    ///
    /// A tuple containing the composite public key and secret key. It is CompositeKEMPublicKey, CompositeKEMPrivateKey
    /// objects in ASN.1 format converted to DER
    fn key_gen_composite(
        &self,
        t_pk: &[u8],
        t_sk: &[u8],
        pq_pk: &[u8],
        pq_sk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Create the composite public key
        let c_pk = CompositePublicKey::new(&self.dsa_info.oid, pq_pk, t_pk);
        let pk = c_pk
            .to_der()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        // Create the OneAsymmetricKey objects for the tradition secret key
        let oid: ObjectIdentifier = self
            .trad_dsa
            .get_dsa_info()
            .oid
            .parse()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
        let t_sk_pkcs8 = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid,
                parameters: None,
            },
            private_key: t_sk,
            public_key: None,
        };

        let oid: ObjectIdentifier = self
            .pq_dsa
            .get_dsa_info()
            .oid
            .parse()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        // Create the OneAsymmetricKey objects for the post-quantum secret key
        let pq_sk_pkcs8 = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid,
                parameters: None,
            },
            private_key: pq_sk,
            public_key: None,
        };

        // Create the composite secret key
        let c_sk = CompositePrivateKey::new(&self.dsa_info.oid, &pq_sk_pkcs8, &t_sk_pkcs8)?;
        let sk = c_sk.to_der()?;

        Ok((pk, sk))
    }
}

impl Dsa for CompositeDsaManager {
    fn new(dsa_type: super::common::dsa_type::DsaType) -> Result<Self>
    where
        Self: Sized,
    {
        let dsa_info = DsaInfo::new(dsa_type.clone());

        let result = match dsa_type {
            DsaType::MlDsa44Rsa2048PssSha256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa2048PssSHA256)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa44)?),
                kdf: MessageDigest::sha256(),
            },
            DsaType::MlDsa44Rsa2048Pkcs15Sha256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa2048Pkcs15SHA256)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa44)?),
                kdf: MessageDigest::sha256(),
            },
            DsaType::MlDsa44Ed25519SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed25519SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa44)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa44EcdsaP256SHA256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP256SHA256)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa44)?),
                kdf: MessageDigest::sha256(),
            },
            DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP256r1SHA256)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa44)?),
                kdf: MessageDigest::sha256(),
            },
            DsaType::MlDsa65Rsa3072PssSHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072PssSHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa65)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa65Rsa3072Pkcs15SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072Pkcs15SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa65)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa65EcdsaP256SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP256SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa65)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP256r1SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa65)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa65Ed25519SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed25519SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa65)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa87EcdsaP384SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP384SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa87)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP384r1SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa87)?),
                kdf: MessageDigest::sha512(),
            },
            DsaType::MlDsa87Ed448SHA512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed448SHA512)?),
                pq_dsa: Box::new(DsaManager::new(DsaType::MlDsa87)?),
                kdf: MessageDigest::sha512(),
            },
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (t_pk, t_sk) = self.trad_dsa.key_gen()?;
        let (pq_pk, pq_sk) = self.pq_dsa.key_gen()?;
        self.key_gen_composite(&t_pk, &t_sk, &pq_pk, &pq_sk)
    }

    fn key_gen_with_rng(
        &mut self,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (t_pk, t_sk) = self.trad_dsa.key_gen_with_rng(rng)?;
        let (pq_pk, pq_sk) = self.pq_dsa.key_gen_with_rng(rng)?;
        self.key_gen_composite(&t_pk, &t_sk, &pq_pk, &pq_sk)
    }

    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let msg = self.pre_hash(msg)?;

        let c_key = CompositePrivateKey::from_der(&self.dsa_info.oid, sk)?;
        let sk_trad = c_key.get_trad_sk()?.private_key;
        let sk_pq = c_key.get_pq_sk()?.private_key;

        let trad_sig = self.trad_dsa.sign(sk_trad, &msg)?;
        let pq_sig = self.pq_dsa.sign(sk_pq, &msg)?;

        let c_sig = CompositeSignatureValue::new(&pq_sig, &trad_sig);

        Ok(c_sig.to_der().unwrap())
    }

    fn verify(&self, pk: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
        let msg = self.pre_hash(msg)?;

        let c_key = CompositePublicKey::from_der(&self.dsa_info.oid, pk)?;

        let trad_pk = c_key.get_trad_pk();
        let pq_pk = c_key.get_pq_pk();

        let c_sig = CompositeSignatureValue::from_der(signature)
            .map_err(|_| QuantCryptError::InvalidSignature)?;
        let t_sig = c_sig.get_trad_sig();
        let pq_sig = c_sig.get_pq_sig();

        let is_verified_trad = self.trad_dsa.verify(&trad_pk, &msg, &t_sig)?;
        let is_verified_pq = self.pq_dsa.verify(&pq_pk, &msg, &pq_sig)?;

        Ok(is_verified_pq && is_verified_trad)
    }

    fn get_dsa_info(&self) -> DsaInfo {
        self.dsa_info.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::dsa::common::macros::test_dsa;

    use super::*;

    #[test]
    fn test_mldsa_44_rsa_2048_pss_sha256() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa44Rsa2048PssSha256);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_rsa_2048_pkcs15_sha256() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa44Rsa2048Pkcs15Sha256);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ed25519_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa44Ed25519SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ecdsa_p256_sha256() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa44EcdsaP256SHA256);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ecdsa_brainpool_p256r1_sha256() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_3072_pss_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa65Rsa3072PssSHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_3072_pkcs15_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa65Rsa3072Pkcs15SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ecdsa_p256_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa65EcdsaP256SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ecdsa_brainpool_p256r1_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ed25519_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa65Ed25519SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_p384_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa87EcdsaP384SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_brainpool_p384r1_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512);
        test_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ed448_sha512() {
        let dsa = CompositeDsaManager::new(DsaType::MlDsa87Ed448SHA512);
        test_dsa!(dsa);
    }
}
