use crate::asn1::composite_private_key::CompositePrivateKey;
use crate::asn1::composite_public_key::CompositePublicKey;
use crate::dsa::asn1::composite_dsa_primitives::CompositeSignatureValue;
use crate::dsa::common::config::label::CompositeLabel;
use crate::dsa::common::prehash_dsa_info::PrehashDsaInfo;
use crate::dsa::dsa_manager::{DsaManager, PrehashDsaManager};

use crate::hash::common::hash_trait::Hash;
use crate::hash::hash_manager::HashManager;
use crate::utils::openssl_utils::{ec_private_key_der_to_scalar, ec_scalar_to_ec_private_key_der};
use crate::QuantCryptError;

use openssl::nid::Nid;
use rand_core::SeedableRng;

use super::common::dsa_trait::Dsa;
use super::common::{
    dsa_type::DsaType, prehash_dsa_trait::PrehashDsa, prehash_dsa_type::PrehashDsaType,
};

type Result<T> = std::result::Result<T, QuantCryptError>;

/// The fixed byte length of the ML-DSA seed stored in a composite private key
/// (draft-19 §4.2).
const ML_DSA_SEED_LEN: usize = 32;

/// Map a traditional signature `DsaType` to the OpenSSL curve `Nid` when it is a
/// prime/Brainpool curve whose composite private key must carry a DER
/// `ECPrivateKey`. Returns `None` for RSA and Edwards curves (which are stored
/// raw / in their own encoding).
fn trad_ec_nid(dsa_type: &DsaType) -> Option<Nid> {
    match dsa_type {
        DsaType::EcdsaP256SHA256 => Some(Nid::X9_62_PRIME256V1),
        DsaType::EcdsaP384SHA384 => Some(Nid::SECP384R1),
        DsaType::EcdsaP521SHA512 => Some(Nid::SECP521R1),
        DsaType::EcdsaBrainpoolP256r1SHA256 => Some(Nid::BRAINPOOL_P256R1),
        DsaType::EcdsaBrainpoolP384r1SHA384 => Some(Nid::BRAINPOOL_P384R1),
        _ => None,
    }
}

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

        // draft-ietf-lamps-pq-composite-sigs-19 Section 2.2:
        //   M' = Prefix || Label || len(ctx) || ctx || PH(M)
        // Prefix is the ASCII string "CompositeAlgorithmSignatures2025".
        const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

        let label = self
            .dsa_info
            .dsa_type
            .get_label()
            .ok_or(QuantCryptError::NotImplemented)?;

        // Every composite algorithm is pre-hashed; PH is fixed per algorithm.
        let hash_type = self
            .dsa_info
            .hash_type
            .clone()
            .ok_or(QuantCryptError::NotImplemented)?;
        let hasher = HashManager::new(hash_type)?;
        let ph = hasher.hash(msg)?;

        let mut tbs_message = Vec::new();
        tbs_message.extend_from_slice(PREFIX);
        tbs_message.extend_from_slice(&label);
        tbs_message.push(ctx_len);
        tbs_message.extend_from_slice(ctx);
        tbs_message.extend_from_slice(&ph);

        Ok(tbs_message)
    }

    /// Get the composite signature Label used as the ML-DSA context and as the
    /// domain separator in the to-be-signed message.
    fn get_label(&self) -> Result<Vec<u8>> {
        self.dsa_info
            .dsa_type
            .get_label()
            .ok_or(QuantCryptError::NotImplemented)
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
    /// The traditional signature `DsaType` backing this composite.
    fn trad_dsa_type(&self) -> DsaType {
        self.trad_dsa.get_dsa_info().dsa_type
    }

    /// Encode a raw traditional secret key into the encoding required by the
    /// composite private key: DER `ECPrivateKey` for prime/Brainpool curves,
    /// otherwise the key as-is (raw Ed25519/Ed448, DER `RSAPrivateKey`).
    fn encode_trad_sk(&self, raw: &[u8]) -> Result<Vec<u8>> {
        if let Some(nid) = trad_ec_nid(&self.trad_dsa_type()) {
            ec_scalar_to_ec_private_key_der(nid, raw)
                .map_err(|_| QuantCryptError::KeyPairGenerationFailed)
        } else {
            Ok(raw.to_vec())
        }
    }

    /// Inverse of [`Self::encode_trad_sk`]: recover the raw traditional secret
    /// key our component signer expects.
    fn decode_trad_sk(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if trad_ec_nid(&self.trad_dsa_type()).is_some() {
            ec_private_key_der_to_scalar(encoded).map_err(|_| QuantCryptError::InvalidPrivateKey)
        } else {
            Ok(encoded.to_vec())
        }
    }

    /// Assemble the composite public and private key encodings from the
    /// traditional key pair and the ML-DSA seed.
    fn assemble_keys(
        &self,
        t_pk: &[u8],
        t_sk_raw: &[u8],
        pq_pk: &[u8],
        pq_seed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let c_pk = CompositePublicKey::new(&self.dsa_info.oid, pq_pk, t_pk);
        let pk = c_pk
            .to_der()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        let t_sk_enc = self.encode_trad_sk(t_sk_raw)?;
        let c_sk = CompositePrivateKey::new(&self.dsa_info.oid, pq_seed, &t_sk_enc);
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
            PrehashDsaType::MlDsa44Rsa2048Pss => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa2048PssSha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa2048Pkcs15Sha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa44Ed25519 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed25519)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa44EcdsaP256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP256SHA256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa44)?),
            },
            PrehashDsaType::MlDsa65Rsa3072Pss => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072PssSha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072Pkcs15Sha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Rsa4096Pss => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa4096PssSha384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa4096Pkcs15Sha384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65EcdsaP256 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP256SHA256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65EcdsaP384 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP384SHA384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP256r1SHA256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa65Ed25519 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed25519)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa65)?),
            },
            PrehashDsaType::MlDsa87EcdsaP384 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP384SHA384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaBrainpoolP384r1SHA384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87Ed448 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Ed448)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87Rsa3072Pss => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa3072PssSha256)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87Rsa4096Pss => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::Rsa4096PssSha384)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            PrehashDsaType::MlDsa87EcdsaP521 => Self {
                dsa_info,
                trad_dsa: Box::new(DsaManager::new(DsaType::EcdsaP521SHA512)?),
                pq_dsa: Box::new(PrehashDsaManager::new(PrehashDsaType::MlDsa87)?),
            },
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        self.key_gen_with_rng(&mut rng)
    }

    fn key_gen_with_rng(
        &mut self,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (t_pk, t_sk_raw) = self.trad_dsa.key_gen_with_rng(rng)?;
        // draft-19: the composite private key stores the 32-byte ML-DSA seed.
        let mut pq_seed = [0u8; ML_DSA_SEED_LEN];
        rng.fill_bytes(&mut pq_seed);
        let (pq_pk, _) = self.pq_dsa.key_gen_from_seed(&pq_seed)?;
        self.assemble_keys(&t_pk, &t_sk_raw, &pq_pk, &pq_seed)
    }

    fn sign_with_ctx(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>> {
        if let Some(ctx) = ctx {
            if ctx.len() > 255 {
                return Err(QuantCryptError::InvalidContext);
            }
        }

        let msg = self.get_tbs_message(msg, ctx)?;

        let c_key = CompositePrivateKey::from_der(&self.dsa_info.oid, sk, ML_DSA_SEED_LEN)?;

        let pq_seed = c_key.get_pq_seed();
        let sk_trad = self.decode_trad_sk(&c_key.get_trad_sk())?;

        // Re-derive the expanded ML-DSA signing key from the stored 32-byte seed.
        let (_, sk_pq) = self.pq_dsa.key_gen_from_seed(&pq_seed)?;

        let trad_sig = self.trad_dsa.sign(&sk_trad, &msg)?;

        // For the PQ algorithm, the composite Label is used as the ML-DSA context.
        let label = self.get_label()?;
        let pq_sig = self.pq_dsa.sign_with_ctx(&sk_pq, &msg, Some(&label))?;

        let c_sig = CompositeSignatureValue::new(&pq_sig, &trad_sig);

        c_sig.to_der()
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

        let pq_pk_len = self
            .pq_dsa
            .get_dsa_info()
            .pk_byte_len
            .ok_or(QuantCryptError::InvalidPublicKey)?;
        let c_key = CompositePublicKey::from_der(&self.dsa_info.oid, pk, pq_pk_len)?;

        let trad_pk = c_key.get_trad_pk();
        let pq_pk = c_key.get_pq_pk();

        let pq_sig_len = self
            .pq_dsa
            .get_dsa_info()
            .sig_byte_len
            .ok_or(QuantCryptError::InvalidSignature)?;
        let c_sig = CompositeSignatureValue::from_der(signature, pq_sig_len)
            .map_err(|_| QuantCryptError::InvalidSignature)?;
        let t_sig = c_sig.get_trad_sig();
        let pq_sig = c_sig.get_pq_sig();

        let is_verified_trad = self.trad_dsa.verify(&trad_pk, &msg, &t_sig)?;

        // For the PQ algorithm, the composite Label is used as the ML-DSA context.
        let label = self.get_label()?;
        let is_verified_pq = self
            .pq_dsa
            .verify_with_ctx(&pq_pk, &msg, &pq_sig, Some(&label))?;

        Ok(is_verified_pq && is_verified_trad)
    }

    fn get_dsa_info(&self) -> PrehashDsaInfo {
        self.dsa_info.clone()
    }

    fn get_public_key(&self, sk: &[u8]) -> Result<Vec<u8>> {
        // Decompose the composite secret key
        let c_key = CompositePrivateKey::from_der(&self.dsa_info.oid, sk, ML_DSA_SEED_LEN)?;

        let pq_seed = c_key.get_pq_seed();
        let sk_trad = self.decode_trad_sk(&c_key.get_trad_sk())?;

        let pk_trad = self.trad_dsa.get_public_key(&sk_trad)?;
        let (pk_pq, _) = self.pq_dsa.key_gen_from_seed(&pq_seed)?;

        let c_pk = CompositePublicKey::new(&self.dsa_info.oid, &pk_pq, &pk_trad);
        c_pk.to_der()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)
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

    // New composite variants added in draft-19.
    #[test]
    fn test_mldsa_65_ecdsa_p256() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa65EcdsaP256);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_rsa_3072_pss() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87Rsa3072Pss);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_rsa_4096_pss() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87Rsa4096Pss);
        test_prehash_dsa!(dsa);
    }

    #[test]
    fn test_mldsa_87_ecdsa_p521() {
        let dsa = CompositeDsaManager::new(PrehashDsaType::MlDsa87EcdsaP521);
        test_prehash_dsa!(dsa);
    }
}
