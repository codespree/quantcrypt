use std::error;

use der::{Decode, Encode, EncodePem};
use der_derive::Sequence;
use pkcs8::{spki::AlgorithmIdentifier, PrivateKeyInfo};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, Sequence)]
/// The public key for the composite KEM
struct CompositePrivateKeyHolder<'a> {
    pq_sk: PrivateKeyInfo<'a>,
    trad_sk: PrivateKeyInfo<'a>,
}

pub struct CompositePrivateKey {
    pq_sk_der: Vec<u8>,
    trad_sk_der: Vec<u8>,
    oid: String,
}

impl CompositePrivateKey {
    /// Create a new composite KEM private key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite KEM
    /// * `pq_sk` - The private key for the post-quantum KEM
    /// * `trad_sk` - The private key for the traditional KEM
    ///
    /// # Returns
    ///
    /// A new composite KEM private key
    pub fn new(
        oid: &str,
        pq_sk: &PrivateKeyInfo<'_>,
        trad_sk: &PrivateKeyInfo<'_>,
    ) -> Result<Self> {
        let pq_sk_der = pq_sk.to_der()?;
        let trad_sk_der = trad_sk.to_der()?;
        Ok(Self {
            pq_sk_der,
            trad_sk_der,
            oid: oid.to_string(),
        })
    }

    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the private key for the post-quantum KEM
    ///
    /// # Returns
    ///
    /// The private key for the post-quantum KEM
    pub fn get_pq_sk(&self) -> Result<PrivateKeyInfo<'_>> {
        Ok(PrivateKeyInfo::from_der(self.pq_sk_der.as_slice())?)
    }

    /// Get the private key for the traditional KEM
    ///
    /// # Returns
    ///
    /// The private key for the traditional KEM
    pub fn get_trad_sk(&self) -> Result<PrivateKeyInfo<'_>> {
        Ok(PrivateKeyInfo::from_der(self.trad_sk_der.as_slice())?)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let parsed = pem::parse(pem)?;
        // Should be -----BEGIN PRIVATE KEY-----
        if parsed.tag() != "PRIVATE KEY" {
            panic!("Expected a private key, got {:?}", parsed.tag());
        }

        CompositePrivateKey::from_der(parsed.contents())
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let top_sk = PrivateKeyInfo::from_der(der)?;
        let top_oid = top_sk.algorithm.oid.to_string();
        let key_data = CompositePrivateKeyHolder::from_der(top_sk.private_key).unwrap();
        CompositePrivateKey::new(&top_oid, &key_data.pq_sk, &key_data.trad_sk)
    }

    pub fn to_pem(&self) -> Result<String> {
        let comp = CompositePrivateKeyHolder {
            pq_sk: self.get_pq_sk()?,
            trad_sk: self.get_trad_sk()?,
        };

        let top_sk = PrivateKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: self.oid.parse().unwrap(),
                parameters: None,
            },
            private_key: &comp.to_der()?,
            public_key: None,
        };
        Ok(top_sk.to_pem(pkcs8::LineEnding::LF)?)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let comp = CompositePrivateKeyHolder {
            pq_sk: self.get_pq_sk()?,
            trad_sk: self.get_trad_sk()?,
        };

        let top_sk = PrivateKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: self.oid.parse().unwrap(),
                parameters: None,
            },
            private_key: &comp.to_der()?,
            public_key: None,
        };
        Ok(top_sk.to_der()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::dsa::common::dsa_type::DsaType;

    use super::*;
    use crate::dsa::common::config::oids::Oid;

    #[test]
    fn test_composite_private_key() {
        let pem_bytes = include_bytes!("../../test/data/mldsa444_ecdsa_p256_sha256_sk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        println!("{}", pem);
        let sk = CompositePrivateKey::from_pem(pem).unwrap();

        let oid = sk.get_oid();
        assert_eq!(oid, DsaType::MlDsa44EcdsaP256SHA256.get_oid());

        let pem2 = sk.to_pem().unwrap();
        //println!("{}", pem2);
        //let pem_bytes2 = pem2.as_bytes();
        assert_eq!(pem, pem2.trim());

        // Test der serialization
        let der = sk.to_der().unwrap();
        let pk2 = CompositePrivateKey::from_der(&der).unwrap();

        let oid2 = pk2.get_oid();
        assert_eq!(oid, oid2);

        let der2 = pk2.to_der().unwrap();
        assert_eq!(der, der2);

        let sk_trad1 = sk.get_trad_sk().unwrap();
        let sk_pq1 = sk.get_pq_sk().unwrap();

        let sk_trad2 = pk2.get_trad_sk().unwrap();
        let sk_pq2 = pk2.get_pq_sk().unwrap();

        assert_eq!(sk_trad1.private_key, sk_trad2.private_key);
        assert_eq!(sk_pq1.private_key, sk_pq2.private_key);
        assert_eq!(sk_trad1.algorithm.oid, sk_trad2.algorithm.oid);
        assert_eq!(sk_pq1.algorithm.oid, sk_pq2.algorithm.oid);
    }
}
