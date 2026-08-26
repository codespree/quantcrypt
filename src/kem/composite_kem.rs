use crate::asn1::composite_private_key::CompositePrivateKey;
use crate::asn1::composite_public_key::CompositePublicKey;
use crate::kem::asn1::composite_kem_primitives::CompositeCiphertextValue;
use crate::kem::common::config::label::CompositeLabel;
use crate::kem::common::kdf::{Kdf, KdfType};
use crate::kem::common::kem_info::KemInfo;
use crate::kem::common::kem_trait::Kem;
use crate::kem::common::kem_type::KemType;
use crate::kem::kem_manager::KemManager;
use crate::utils::openssl_utils::{
    ec_private_key_der_to_scalar, ec_scalar_to_ec_private_key_der, get_pk_from_sk_ec_based,
    get_pk_from_sk_pkey_based,
};
use crate::QuantCryptError;
use openssl::nid::Nid;
use openssl::pkey::Id;
use rand_core::{CryptoRngCore, SeedableRng};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::RsaPrivateKey;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// The fixed byte length of the ML-KEM seed (`d || z`) stored in a composite
/// private key (draft-15 §4.2).
const ML_KEM_SEED_LEN: usize = 64;

/// Map a traditional KEM `KemType` to the OpenSSL curve `Nid` when its composite
/// private key must carry a DER `ECPrivateKey`. Returns `None` for RSA and the
/// Montgomery curves X25519/X448 (stored raw).
fn trad_ec_nid(kem_type: &KemType) -> Option<Nid> {
    match kem_type {
        KemType::P256 => Some(Nid::X9_62_PRIME256V1),
        KemType::P384 => Some(Nid::SECP384R1),
        KemType::P521 => Some(Nid::SECP521R1),
        KemType::BrainpoolP256r1 => Some(Nid::BRAINPOOL_P256R1),
        KemType::BrainpoolP384r1 => Some(Nid::BRAINPOOL_P384R1),
        _ => None,
    }
}

/// A KEM manager for the composite KEM method
pub struct CompositeKemManager {
    /// The KEM metadata information
    kem_info: KemInfo,
    /// The traditional KEM manager
    trad_kem: Box<KemManager>,
    /// The post-quantum KEM manager
    pq_kem: Box<KemManager>,
    /// The key derivation function
    kdf: Kdf,
}

impl CompositeKemManager {
    /// See the combiner function in the RFC:
    /// https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
    ///
    /// The combiner function is used to combine the shared secrets from the traditional and post-quantum KEMs
    ///
    /// # Arguments
    ///
    /// * `pq_kem_ss` - The shared secret from the post-quantum KEM
    /// * `trad_kem_ss` - The shared secret from the traditional KEM
    /// * `trad_ct` - The traditional ciphertext
    /// * `trad_pk` - The traditional public key (this should exist in the OneAsymmetricKey object)
    ///
    /// # Returns
    ///
    /// The combined shared secret (ss) after applying the KDF
    pub fn combiner(
        &self,
        pq_kem_ss: &[u8],
        trad_kem_ss: &[u8],
        trad_ct: &[u8],
        trad_pk: &[u8],
    ) -> Result<Vec<u8>> {
        // draft-ietf-lamps-pq-composite-kem-15 Section 3.4:
        //   ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)
        let mut combined_ss: Vec<u8> = Vec::new();
        combined_ss.extend_from_slice(pq_kem_ss);
        combined_ss.extend_from_slice(trad_kem_ss);
        combined_ss.extend_from_slice(trad_ct);
        combined_ss.extend_from_slice(trad_pk);

        let label = self
            .kem_info
            .kem_type
            .get_label()
            .ok_or(QuantCryptError::NotImplemented)?;
        combined_ss.extend_from_slice(&label);

        let ss = self.kdf.kdf(&combined_ss);

        Ok(ss)
    }

    /// Generate a composite KEM keypair from constituent keys
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
    /// The traditional KEM `KemType` backing this composite.
    fn trad_kem_type(&self) -> KemType {
        self.trad_kem.get_kem_info().kem_type
    }

    /// Encode a raw traditional secret key into the encoding required by the
    /// composite private key: DER `ECPrivateKey` for prime/Brainpool curves,
    /// otherwise the key as-is (raw X25519/X448, DER `RSAPrivateKey`).
    fn encode_trad_sk(&self, raw: &[u8]) -> Result<Vec<u8>> {
        if let Some(nid) = trad_ec_nid(&self.trad_kem_type()) {
            ec_scalar_to_ec_private_key_der(nid, raw)
                .map_err(|_| QuantCryptError::KeyPairGenerationFailed)
        } else {
            Ok(raw.to_vec())
        }
    }

    /// Inverse of [`Self::encode_trad_sk`]: recover the raw traditional secret
    /// key our component decapsulator expects.
    fn decode_trad_sk(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if trad_ec_nid(&self.trad_kem_type()).is_some() {
            ec_private_key_der_to_scalar(encoded).map_err(|_| QuantCryptError::InvalidPrivateKey)
        } else {
            Ok(encoded.to_vec())
        }
    }

    /// Derive the traditional public key from the raw traditional secret key.
    /// The composite KEM combiner needs `tradPK`, but draft-15 private keys do
    /// not store it, so it is recomputed from the secret key on decapsulation.
    /// The encoding matches what key generation places in the composite public
    /// key (uncompressed EC point / raw Montgomery key / DER `RSAPublicKey`).
    fn derive_trad_pk(&self, trad_sk_raw: &[u8]) -> Result<Vec<u8>> {
        let result = match self.trad_kem_type() {
            KemType::P256 => get_pk_from_sk_ec_based(trad_sk_raw, Nid::X9_62_PRIME256V1),
            KemType::P384 => get_pk_from_sk_ec_based(trad_sk_raw, Nid::SECP384R1),
            KemType::P521 => get_pk_from_sk_ec_based(trad_sk_raw, Nid::SECP521R1),
            KemType::BrainpoolP256r1 => get_pk_from_sk_ec_based(trad_sk_raw, Nid::BRAINPOOL_P256R1),
            KemType::BrainpoolP384r1 => get_pk_from_sk_ec_based(trad_sk_raw, Nid::BRAINPOOL_P384R1),
            KemType::X25519 => get_pk_from_sk_pkey_based(trad_sk_raw, Id::X25519),
            KemType::X448 => get_pk_from_sk_pkey_based(trad_sk_raw, Id::X448),
            KemType::RsaOAEP2048 | KemType::RsaOAEP3072 | KemType::RsaOAEP4096 => {
                let sk = RsaPrivateKey::from_pkcs1_der(trad_sk_raw)
                    .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
                let der = sk
                    .to_public_key()
                    .to_pkcs1_der()
                    .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
                return Ok(der.as_bytes().to_vec());
            }
            _ => return Err(QuantCryptError::NotImplemented),
        };
        result.map_err(|_| QuantCryptError::DecapFailed)
    }

    /// Assemble the composite public and private key encodings from the
    /// traditional key pair and the ML-KEM seed.
    fn assemble_keys(
        &self,
        t_pk: &[u8],
        t_sk_raw: &[u8],
        pq_ek: &[u8],
        pq_seed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let c_pk = CompositePublicKey::new(&self.kem_info.oid, pq_ek, t_pk);
        let pk = c_pk.to_der()?;

        let t_sk_enc = self.encode_trad_sk(t_sk_raw)?;
        let c_sk = CompositePrivateKey::new(&self.kem_info.oid, pq_seed, &t_sk_enc);
        let sk = c_sk.to_der()?;

        Ok((pk, sk))
    }
}

impl Kem for CompositeKemManager {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    ///
    /// # Returns
    ///
    /// A new KEM instance
    fn new(kem_type: KemType) -> Result<Self> {
        let kem_info = KemInfo::new(kem_type.clone());
        let result = match kem_type {
            KemType::MlKem768Rsa2048 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::RsaOAEP2048)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem768Rsa3072 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::RsaOAEP3072)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem768Rsa4096 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::RsaOAEP4096)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem768X25519 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::X25519)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem768P384 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::P384)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem768BrainpoolP256r1 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::BrainpoolP256r1)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem1024P384 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::P384)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem1024)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem1024BrainpoolP384r1 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::BrainpoolP384r1)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem1024)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem1024X448 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::X448)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem1024)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem768P256 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::P256)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem768)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem1024Rsa3072 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::RsaOAEP3072)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem1024)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            KemType::MlKem1024P521 => Self {
                kem_info,
                trad_kem: Box::new(KemManager::new(KemType::P521)?),
                pq_kem: Box::new(KemManager::new(KemType::MlKem1024)?),
                kdf: Kdf::new(KdfType::Sha3_256),
            },
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    /// Generate a composite KEM keypair using the default RNGs of the
    /// traditional and post-quantum KEMs of the composite KEM
    ///
    /// # Returns
    ///
    /// A tuple containing the composite public key and secret key (pk, sk).
    /// It is CompositeKEMPublicKey, CompositeKEMPrivateKey objects in ASN.1
    /// format converted to DER
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        self.key_gen_with_rng(&mut rng)
    }

    /// Generate a composite KEM keypair
    ///
    /// # Arguments
    ///
    /// * `rng` - The random number generator to use
    ///
    /// # Returns
    ///
    /// A tuple containing the composite public key and secret key (pk, sk).
    /// It is CompositeKEMPublicKey, CompositeKEMPrivateKey objects in ASN.1
    /// format converted to DER
    ///
    /// The keys are composite keys in ASN.1 format:
    /// CompositeKEMPublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
    /// CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
    ///
    /// OneAsymmetricKey ::= SEQUENCE {
    ///    version                   Version,
    ///    privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    ///    privateKey                PrivateKey,
    ///    attributes            [0] Attributes OPTIONAL,
    ///    ...,
    ///    [[2: publicKey        [1] PublicKey OPTIONAL ]],
    ///    ...
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        // Get the keypair for the traditional KEM
        let (t_pk, t_sk_raw) = self.trad_kem.key_gen_with_rng(rng)?;

        // draft-15: the composite private key stores the 64-byte ML-KEM seed
        // (d || z); the encapsulation key is derived from it.
        let mut pq_seed = [0u8; ML_KEM_SEED_LEN];
        rng.fill_bytes(&mut pq_seed);
        let (pq_ek, _) = self.pq_kem.key_gen_from_seed(&pq_seed)?;

        self.assemble_keys(&t_pk, &t_sk_raw, &pq_ek, &pq_seed)
    }

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The composite public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the shared secret and ciphertext (ss, ct).
    /// The shared secret is the result of the combiner function, and the
    /// ciphertext is the CompositeCiphertextValue in ASN.1 format converted to DER
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Deserialize the composite public key
        let pq_pk_len = self
            .pq_kem
            .get_kem_info()
            .pk_byte_len
            .ok_or(QuantCryptError::InvalidPublicKey)?;
        let c_pk = CompositePublicKey::from_der(&self.kem_info.oid, pk, pq_pk_len)?;

        // Encapsulate the public key for the traditional KEM
        let (t_ss, t_ct) = self.trad_kem.encap(&c_pk.get_trad_pk())?;

        // Encapsulate the public key for the post-quantum KEM
        let (pq_ss, pq_ct) = self.pq_kem.encap(&c_pk.get_pq_pk())?;

        // Create the composite ciphertext
        let ct = CompositeCiphertextValue::new(&pq_ct, &t_ct);
        let ct = ct.to_der().map_err(|_| QuantCryptError::EncapFailed)?;

        // Get the shared secret using the combiner
        let ss = self.combiner(&pq_ss, &t_ss, &t_ct, &c_pk.get_trad_pk())?;

        Ok((ss, ct))
    }

    /// Decapsulate a ciphertext
    ///
    /// # Arguments
    ///
    /// * `sk` - The composite secret key to decapsulate - CompositeKEMPrivateKey in ASN.1 format converted to DER
    /// * `ct` - The composite ciphertext to decapsulate - CompositeCiphertextValue in ASN.1 format converted to DER
    ///
    /// # Returns
    ///
    /// The shared secret after applying the combiner function
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        // Deserialize the composite secret key: mlkemSeed(64) || tradSK.
        let c_sk = CompositePrivateKey::from_der(&self.kem_info.oid, sk, ML_KEM_SEED_LEN)?;
        let pq_seed = c_sk.get_pq_seed();
        let trad_sk_raw = self.decode_trad_sk(&c_sk.get_trad_sk())?;

        // Deserialize the composite ciphertext, splitting at the ML-KEM
        // ciphertext length.
        let pq_ct_len = self
            .pq_kem
            .get_kem_info()
            .ct_byte_len
            .ok_or(QuantCryptError::DecapFailed)?;
        let c_ct = CompositeCiphertextValue::from_der(ct, pq_ct_len)
            .map_err(|_| QuantCryptError::DecapFailed)?;

        // Decapsulate the ciphertext for the traditional KEM
        let t_ss = self.trad_kem.decap(&trad_sk_raw, &c_ct.get_trad_ct())?;

        // Re-derive the ML-KEM decapsulation key from the stored seed, then
        // decapsulate the post-quantum ciphertext.
        let (_, pq_dk) = self.pq_kem.key_gen_from_seed(&pq_seed)?;
        let pq_ss = self.pq_kem.decap(&pq_dk, &c_ct.get_pq_ct())?;

        // The combiner requires tradPK, which draft-15 private keys do not
        // store, so it is recomputed from the traditional secret key.
        let t_pk = self.derive_trad_pk(&trad_sk_raw)?;

        // Get the shared secret using the combiner
        let ss = self.combiner(&pq_ss, &t_ss, &c_ct.get_trad_ct(), &t_pk)?;

        Ok(ss)
    }

    /// Get KEM metadata information such as the key lengths,
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
    use crate::kem::common::macros::test_kem;

    #[test]
    fn test_mlkem_768_rsa2048() {
        let kem = CompositeKemManager::new(KemType::MlKem768Rsa2048);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_768_rsa3072() {
        let kem = CompositeKemManager::new(KemType::MlKem768Rsa3072);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_768_rsa4096() {
        let kem = CompositeKemManager::new(KemType::MlKem768Rsa4096);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_768_x25519() {
        let kem = CompositeKemManager::new(KemType::MlKem768X25519);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_768_p384() {
        let kem = CompositeKemManager::new(KemType::MlKem768P384);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_768_brainpool_p256r1() {
        let kem = CompositeKemManager::new(KemType::MlKem768BrainpoolP256r1);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_1024_p384() {
        let kem = CompositeKemManager::new(KemType::MlKem1024P384);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_1024_brainpool_p384r1() {
        let kem = CompositeKemManager::new(KemType::MlKem1024BrainpoolP384r1);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_1024_x448() {
        let kem = CompositeKemManager::new(KemType::MlKem1024X448);
        test_kem!(kem);
    }

    // New composite variants added in draft-15.
    #[test]
    fn test_mlkem_768_p256() {
        let kem = CompositeKemManager::new(KemType::MlKem768P256);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_1024_rsa3072() {
        let kem = CompositeKemManager::new(KemType::MlKem1024Rsa3072);
        test_kem!(kem);
    }

    #[test]
    fn test_mlkem_1024_p521() {
        let kem = CompositeKemManager::new(KemType::MlKem1024P521);
        test_kem!(kem);
    }

    /// Byte-for-byte validation of the SHA3-256 KEM combiner against the
    /// intermediate-value example for id-MLKEM768-ECDH-P256-SHA3-256 in
    /// draft-ietf-lamps-pq-composite-kem-15 Appendix E. Confirms the combiner
    /// input order (mlkemSS || tradSS || tradCT || tradPK || Label), the Label
    /// bytes ("MLKEM768-P256"), and the SHA3-256 output.
    #[test]
    fn test_kem_combiner_vector_mlkem768_p256() {
        let mlkem_ss =
            hex::decode("ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43")
                .unwrap();
        let trad_ss =
            hex::decode("ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0")
                .unwrap();
        let trad_ct = hex::decode(
            "041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d19171270cdefcd4abb6\
             82edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5e7610",
        )
        .unwrap();
        let trad_pk = hex::decode(
            "04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159ff73d38d29aa9\
             4f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e80396a3e",
        )
        .unwrap();
        let expected_ss =
            hex::decode("d6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee")
                .unwrap();

        let kem = CompositeKemManager::new(KemType::MlKem768P256).unwrap();
        let ss = kem
            .combiner(&mlkem_ss, &trad_ss, &trad_ct, &trad_pk)
            .unwrap();
        assert_eq!(ss, expected_ss);
    }
}
