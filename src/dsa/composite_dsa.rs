use crate::asn1::asn_util::oid_to_der;
use crate::asn1::composite_private_key::CompositePrivateKey;
use crate::asn1::composite_public_key::CompositePublicKey;
use crate::dsa::asn1::composite_dsa_primitives::CompositeSignatureValue;
use crate::dsa::common::prehash_dsa_info::PrehashDsaInfo;
use crate::dsa::dsa_manager::{DsaManager, PrehashDsaManager};

use crate::hash::common::hash_trait::Hash;
use crate::hash::hash_manager::HashManager;
use crate::QuantCryptError;

use der::asn1::OctetString;
use der::{Decode, Encode};

use super::common::dsa_trait::Dsa;
use super::common::{
    dsa_type::DsaType, prehash_dsa_trait::PrehashDsa, prehash_dsa_type::PrehashDsaType,
};

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A DSA manager for the composite DSA method
#[derive(Clone)]
pub struct CompositeDsaManager {
    /// The DSA metadata information
    dsa_info: PrehashDsaInfo,
    /// The traditional DSA manager
    trad_dsa: Box<DsaManager>,
    /// The post-quantum DSA manager
    pq_dsa: Box<PrehashDsaManager>,
}

impl CompositeDsaManager {
    /// Get's the message that is to be signed after pre-hashing and adding the domain
    /// as may be required by the DSA algorithm
    ///
    /// # Arguments
    ///
    /// * `msg` - the message to pre-hash
    ///
    /// # Returns
    ///
    /// The pre-hashed message
    fn get_tbs_message(&self, msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>> {
        let ctx = ctx.unwrap_or(&[]);

        // The context is less than 255 bytes so represent its length in a single byte
        let ctx_len = ctx.len() as u8;

        let mut tbs_message = oid_to_der(&self.dsa_info.oid)?;
        tbs_message.extend_from_slice(&[ctx_len]);
        tbs_message.extend_from_slice(ctx);

        if let Some(hash_type) = self.dsa_info.hash_type.clone() {
            let hasher = HashManager::new(hash_type)?;
            let hash = hasher.hash(msg)?;
            let hash_oid = hasher.get_hash_info().oid;
            let hash_oid = oid_to_der(&hash_oid)?;
            tbs_message.extend_from_slice(&hash_oid);
            tbs_message.extend_from_slice(&hash);
        } else {
            tbs_message.extend_from_slice(msg);
        }
        let msg = tbs_message;
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

        // Create the OctetString objects for the secret keys
        let pq_sk_der =
            OctetString::new(pq_sk).map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        let t_sk_der =
            OctetString::new(t_sk).map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        // Create the composite secret key
        let c_sk = CompositePrivateKey::new_dsa(&self.dsa_info.oid, &pq_sk_der, &t_sk_der)?;
        let sk = c_sk.to_der()?;

        Ok((pk, sk))
    }
}

impl PrehashDsa for CompositeDsaManager {
    fn new(dsa_type: super::common::prehash_dsa_type::PrehashDsaType) -> Result<Self>
    where
        Self: Sized,
    {
        let dsa_info = PrehashDsaInfo::new(dsa_type.clone());

        let result = match dsa_type {
            PrehashDsaType::MlDsa44Rsa2048Pss | PrehashDsaType::MlDsa44Rsa2048PssSha256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa2048PssSha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 | PrehashDsaType::MlDsa44Rsa2048Pkcs15Sha256 => {
                Self {
                    dsa_info,
                    trad_dsa: Box::new(DsaManager::new(DsaType::Rsa2048Pkcs15Sha256)?),
                    pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
                }
            }
            PrehashDsaType::MlDsa44Ed25519 | PrehashDsaType::MlDsa44Ed25519Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed25519)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa44EcdsaP256 | PrehashDsaType::MlDsa44EcdsaP256Sha256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP256SHA256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa65Rsa3072Pss | PrehashDsaType::MlDsa65Rsa3072PssSha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072PssSha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 | PrehashDsaType::MlDsa65Rsa3072Pkcs15Sha512 => {
                Self {
                    dsa_info,
                    trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072Pkcs15Sha256)?),
                    pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
                }
            }
            PrehashDsaType::MlDsa65Rsa4096Pss | PrehashDsaType::MlDsa65Rsa4096PssSha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa4096PssSha384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 | PrehashDsaType::MlDsa65Rsa4096Pkcs15Sha512 => {
                Self {
                    dsa_info,
                    trad_dsa: Box::new(DsaManager::new(DsaType::Rsa4096Pkcs15Sha384)?),
                    pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
                }
            }
            PrehashDsaType::MlDsa65EcdsaP384 | PrehashDsaType::MlDsa65EcdsaP384Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP384SHA384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1
            | PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP256r1SHA256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Ed25519 | PrehashDsaType::MlDsa65Ed25519Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed25519)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa87EcdsaP384 | PrehashDsaType::MlDsa87EcdsaP384Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP384SHA384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1
            | PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP384r1SHA384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87Ed448 | PrehashDsaType::MlDsa87Ed448Sha512 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed448)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
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

    fn sign_with_ctx(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>> {
        if let Some(ctx) = ctx {
            if ctx.len() > 255 {
                return Err(QuantCryptError::InvalidContext);
            }
        }

        let msg = self.get_tbs_message(msg, ctx)?;

        let c_key = CompositePrivateKey::from_der(&self.dsa_info.oid, sk)?;

        let sk_trad_os: OctetString = c_key.get_dsa_trad_sk()?;
        let sk_pq_os = c_key.get_dsa_pq_sk()?;

        let sk_trad = sk_trad_os.as_bytes();
        let sk_pq = sk_pq_os.as_bytes();

        let trad_sig = self.trad_dsa.sign(sk_trad, &msg)?;

        // For the PQ algorithm, use the domain as the context
        let domain = oid_to_der(&self.dsa_info.oid)?;
        let pq_sig = self.pq_dsa.sign_with_ctx(sk_pq, &msg, Some(&domain))?;

        let c_sig = CompositeSignatureValue::new(&pq_sig, &trad_sig);

        Ok(c_sig.to_der().unwrap())
    }

    fn verify_with_ctx(
        &self,
        pk: &[u8],
        msg: &[u8],
        signature: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<bool> {
        if let Some(ctx) = ctx {
            if ctx.len() > 255 {
                return Err(QuantCryptError::InvalidContext);
            }
        }

        let msg = self.get_tbs_message(msg, ctx)?;

        let c_key = CompositePublicKey::from_der(&self.dsa_info.oid, pk)?;

        let trad_pk = c_key.get_trad_pk();
        let pq_pk = c_key.get_pq_pk();

        let c_sig = CompositeSignatureValue::from_der(signature)
            .map_err(|_| QuantCryptError::InvalidSignature)?;
        let t_sig = c_sig.get_trad_sig();
        let pq_sig = c_sig.get_pq_sig();

        let is_verified_trad = self.trad_dsa.verify(&trad_pk, &msg, &t_sig)?;

        // For the PQ algorithm, use the domain as the context
        let domain = oid_to_der(&self.dsa_info.oid)?;
        let is_verified_pq = self
            .pq_dsa
            .verify_with_ctx(&pq_pk, &msg, &pq_sig, Some(&domain))?;

        Ok(is_verified_pq && is_verified_trad)
    }

    fn get_dsa_info(&self) -> PrehashDsaInfo {
        self.dsa_info.clone()
    }

    fn get_public_key(&self, sk: &[u8]) -> Result<Vec<u8>> {
        // Decompose the composite secret key
        let c_key = CompositePrivateKey::from_der(&self.dsa_info.oid, sk)?;

        let sk_trad_os = c_key.get_dsa_trad_sk()?;
        let sk_pq_os = c_key.get_dsa_pq_sk()?;

        let sk_trad = sk_trad_os.as_bytes();
        let sk_pq = sk_pq_os.as_bytes();

        let pk_trad = self.trad_dsa.get_public_key(sk_trad)?;
        let pk_pq = self.pq_dsa.get_public_key(sk_pq)?;

        let c_pk = CompositePublicKey::new(&self.dsa_info.oid, &pk_pq, &pk_trad);
        let pk = c_pk
            .to_der()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        Ok(pk)
    }
}

#[cfg(test)]
mod tests {
    use crate::dsa::common::macros::test_prehash_dsa;

    use super::*;

    #[test]
    fn test_mldsa_44_rsa_2048_pss() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44Rsa2048Pss);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_rsa_2048_pkcs15() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44Rsa2048Pkcs15);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ed25519() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44Ed25519);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ecdsa_p256() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44EcdsaP256);
        test_prehash_dsa!(dsa);
    }
    #[test]
    fn test_mldsa_65_rsa_3072_pss() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa3072Pss);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_3072_pkcs15() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa3072Pkcs15);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_4096_pss() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa4096Pss);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_4096_pkcs15() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa4096Pkcs15);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ecdsa_p384() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65EcdsaP384);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ecdsa_brainpool_p256r1() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ed25519() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Ed25519);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_p384() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87EcdsaP384);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_brainpool_p384r1() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ed448() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87Ed448);
        test_prehash_dsa!(dsa);
    }

    ///////////////// Test the pre-hash versions of the above algorithms //////////////////////
    #[test]
    fn test_mldsa_44_rsa_2048_pss_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44Rsa2048PssSha256);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_rsa_2048_pkcs15_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44Rsa2048Pkcs15Sha256);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ed25519_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44Ed25519Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_44_ecdsa_p256_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa44EcdsaP256Sha256);
        test_prehash_dsa!(dsa);
    }
    #[test]
    fn test_mldsa_65_rsa_3072_pss_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa3072PssSha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_3072_pkcs15_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa3072Pkcs15Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_4096_pss_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa4096PssSha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_rsa_4096_pkcs15_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Rsa4096Pkcs15Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ecdsa_p384_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65EcdsaP384Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ecdsa_brainpool_p256r1_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_65_ed25519_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65Ed25519Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_p384_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87EcdsaP384Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_brainpool_p384r1_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1Sha512);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ed448_ph() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87Ed448Sha512);
        test_prehash_dsa!(dsa);
    }
}
