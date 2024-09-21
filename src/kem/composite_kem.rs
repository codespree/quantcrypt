use crate::kem::asn1::asn_util::oid_to_der;
use crate::kem::asn1::composite_kem_primitives::{
    CompositeCiphertextValue, CompositeKEMPrivateKey, CompositeKEMPublicKey,
};
use crate::kem::ec_kem::DhKemManager;
use crate::kem::kdf::{KdfType, KDF};
use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use crate::kem::ml_kem::MlKemManager;
use crate::kem::rsa_kem::RsaKemManager;
use der::{Decode, Encode};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};

use std::error;
// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub struct CompositeKem {
    kem_type: KemType,
    trad_kem: Box<dyn Kem>,
    pq_kem: Box<dyn Kem>,
    kdf: KDF,
}

fn get_kem(kem_type: KemType) -> Box<dyn Kem> {
    match kem_type {
        KemType::BrainpoolP256r1 => Box::new(DhKemManager::new(KemType::BrainpoolP256r1)),
        KemType::BrainpoolP384r1 => Box::new(DhKemManager::new(KemType::BrainpoolP384r1)),
        KemType::P256 => Box::new(DhKemManager::new(KemType::P256)),
        KemType::P384 => Box::new(DhKemManager::new(KemType::P384)),
        KemType::X25519 => Box::new(DhKemManager::new(KemType::X25519)),
        KemType::X448 => Box::new(DhKemManager::new(KemType::X448)),
        KemType::RsaOAEP2048 => Box::new(RsaKemManager::new(KemType::RsaOAEP2048)),
        KemType::RsaOAEP3072 => Box::new(RsaKemManager::new(KemType::RsaOAEP3072)),
        KemType::RsaOAEP4096 => Box::new(RsaKemManager::new(KemType::RsaOAEP4096)),
        KemType::MlKem512 => Box::new(MlKemManager::new(KemType::MlKem512)),
        KemType::MlKem768 => Box::new(MlKemManager::new(KemType::MlKem768)),
        KemType::MlKem1024 => Box::new(MlKemManager::new(KemType::MlKem1024)),
        _ => {
            panic!("Not implemented");
        }
    }
}

impl CompositeKem {
    pub fn combiner(
        &self,
        pq_kem_ss: &[u8],
        trad_kem_ss: &[u8],
        trad_ct: &[u8],
        trad_pk: &[u8],
    ) -> Result<Vec<u8>> {
        let mut combined_ss: Vec<u8> = Vec::new();
        combined_ss.extend_from_slice(pq_kem_ss);
        combined_ss.extend_from_slice(trad_kem_ss);
        combined_ss.extend_from_slice(trad_ct);
        combined_ss.extend_from_slice(trad_pk);

        let dom_sep = oid_to_der(&self.get_oid())?;
        combined_ss.extend_from_slice(&dom_sep);

        let ss = self.kdf.kdf(&combined_ss);

        Ok(ss)
    }
}

impl Kem for CompositeKem {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    ///
    /// # Returns
    ///
    /// A new KEM instance
    ///
    /// # Panics
    ///
    /// If the KEM type is not supported (should be a composite KEM)
    fn new(kem_type: KemType) -> Self {
        match kem_type {
            KemType::MlKem768Rsa2048 => Self {
                kem_type,
                trad_kem: get_kem(KemType::RsaOAEP2048),
                pq_kem: get_kem(KemType::MlKem768),
                kdf: KDF::new(KdfType::HkdfSha256),
            },
            KemType::MlKem768Rsa3072 => Self {
                kem_type,
                trad_kem: get_kem(KemType::RsaOAEP3072),
                pq_kem: get_kem(KemType::MlKem768),
                kdf: KDF::new(KdfType::HkdfSha256),
            },
            KemType::MlKem768Rsa4096 => Self {
                kem_type,
                trad_kem: get_kem(KemType::RsaOAEP4096),
                pq_kem: get_kem(KemType::MlKem768),
                kdf: KDF::new(KdfType::HkdfSha256),
            },
            KemType::MlKem768X25519 => Self {
                kem_type,
                trad_kem: get_kem(KemType::X25519),
                pq_kem: get_kem(KemType::MlKem768),
                kdf: KDF::new(KdfType::Sha3_256),
            },
            KemType::MlKem768P384 => Self {
                kem_type,
                trad_kem: get_kem(KemType::P384),
                pq_kem: get_kem(KemType::MlKem768),
                kdf: KDF::new(KdfType::HkdfSha384),
            },
            KemType::MlKem768BrainpoolP256r1 => Self {
                kem_type,
                trad_kem: get_kem(KemType::BrainpoolP256r1),
                pq_kem: get_kem(KemType::MlKem768),
                kdf: KDF::new(KdfType::HkdfSha384),
            },
            KemType::MlKem1024P384 => Self {
                kem_type,
                trad_kem: get_kem(KemType::P384),
                pq_kem: get_kem(KemType::MlKem1024),
                kdf: KDF::new(KdfType::Sha3_512),
            },
            KemType::MlKem1024BrainpoolP384r1 => Self {
                kem_type,
                trad_kem: get_kem(KemType::BrainpoolP384r1),
                pq_kem: get_kem(KemType::MlKem1024),
                kdf: KDF::new(KdfType::Sha3_512),
            },
            KemType::MlKem1024X448 => Self {
                kem_type,
                trad_kem: get_kem(KemType::X448),
                pq_kem: get_kem(KemType::MlKem1024),
                kdf: KDF::new(KdfType::Sha3_512),
            },
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Generate a composite KEM keypair
    ///
    /// # Returns
    ///
    /// A tuple containing the public key and secret key
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
    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
        // Get the keypair for the traditional KEM
        let (t_pk, t_sk) = self.trad_kem.key_gen(seed)?;

        // Get the keypair for the post-quantum KEM
        let (pq_pk, pq_sk) = self.pq_kem.key_gen(seed)?;

        // Create the composite public key
        let c_pk = CompositeKEMPublicKey::new(&pq_pk, &t_pk);
        let pk = c_pk.to_der()?;

        // Create the OneAsymmetricKey objects for the tradition secret key
        let t_sk_pkcs8 = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid: self.trad_kem.get_oid().parse().unwrap(),
                parameters: None,
            },
            private_key: &t_sk,
            public_key: Some(&t_pk),
        };

        // Create the OneAsymmetricKey objects for the post-quantum secret key
        let pq_sk_pkcs8 = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid: self.pq_kem.get_oid().parse().unwrap(),
                parameters: None,
            },
            private_key: &pq_sk,
            public_key: None,
        };

        // Create the composite secret key
        let c_sk = CompositeKEMPrivateKey::new(pq_sk_pkcs8, t_sk_pkcs8);
        let sk = c_sk.to_der()?;

        Ok((pk, sk))
    }

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The composite public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the ciphertext and shared secret
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Deserialize the composite public key
        let c_pk = CompositeKEMPublicKey::from_der(pk)?;

        // Encapsulate the public key for the traditional KEM
        let (t_ss, t_ct) = self.trad_kem.encap(&c_pk.get_trad_pk())?;

        // Encapsulate the public key for the post-quantum KEM
        let (pq_ss, pq_ct) = self.pq_kem.encap(&c_pk.get_pq_pk())?;

        // Create the composite ciphertext
        let ct = CompositeCiphertextValue::new(&pq_ct, &t_ct);
        let ct = ct.to_der()?;

        // Get the shared secret using the combiner
        let ss = self.combiner(&pq_ss, &t_ss, &t_ct, &c_pk.get_trad_pk())?;

        Ok((ss, ct))
    }

    /// Decapsulate a ciphertext
    ///
    /// # Arguments
    ///
    /// * `sk` - The composite secret key to decapsulate with
    /// * `ct` - The composite ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The shared secret
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        // Deserialize the composite secret key
        let c_sk = CompositeKEMPrivateKey::from_der(sk).unwrap();

        // Deserialize the composite ciphertext
        let c_ct = CompositeCiphertextValue::from_der(ct).unwrap();

        // Decapsulate the ciphertext for the traditional KEM
        let t_ss = self
            .trad_kem
            .decap(c_sk.get_trad_sk().private_key, &c_ct.get_trad_ct())
            .unwrap();

        // Decapsulate the ciphertext for the post-quantum KEM
        let pq_ss = self
            .pq_kem
            .decap(c_sk.get_pq_sk().private_key, &c_ct.get_pq_ct())
            .unwrap();

        // Get the trad PK
        let t_pk = c_sk.get_trad_sk().public_key.unwrap();

        // Get the shared secret using the combiner
        let ss = self
            .combiner(&pq_ss, &t_ss, &c_ct.get_trad_ct(), t_pk)
            .unwrap();

        Ok(ss)
    }

    fn get_ss_byte_len(&self) -> usize {
        // SS length is based on the KDF
        self.kdf.get_output_len()
    }

    fn get_ct_byte_len(&self) -> Option<usize> {
        //TODO: Confirm the length of the composite ciphertext
        None
    }

    fn get_pk_byte_len(&self) -> Option<usize> {
        //TODO: Confirm the length of the composite public key
        None
    }

    fn get_sk_byte_len(&self) -> Option<usize> {
        None
    }

    fn get_kem_type(&self) -> KemType {
        self.kem_type.clone()
    }

    fn get_oid(&self) -> String {
        let oid = match self.kem_type {
            KemType::MlKem768Rsa2048 => "2.16.840.1.114027.80.5.2.21",
            KemType::MlKem768Rsa3072 => "2.16.840.1.114027.80.5.2.22",
            KemType::MlKem768Rsa4096 => "2.16.840.1.114027.80.5.2.23",
            KemType::MlKem768X25519 => "2.16.840.1.114027.80.5.2.24",
            KemType::MlKem768P384 => "2.16.840.1.114027.80.5.2.25",
            KemType::MlKem768BrainpoolP256r1 => "2.16.840.1.114027.80.5.2.26",
            KemType::MlKem1024P384 => "2.16.840.1.114027.80.5.2.27",
            KemType::MlKem1024BrainpoolP384r1 => "2.16.840.1.114027.80.5.2.28",
            KemType::MlKem1024X448 => "2.16.840.1.114027.80.5.2.29",
            _ => {
                panic!("Not implemented");
            }
        };
        oid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::macros::test_kem;

    #[test]
    fn test_composite_kems() {
        let kems = vec![
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

        for kem_type in kems {
            let mut kem = CompositeKem::new(kem_type.clone());
            test_kem!(&mut kem);
        }
    }
}
