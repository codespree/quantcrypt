use std::error;

use der::zeroize::Zeroize;
use der::{Decode, Encode, EncodePem};
use der_derive::Sequence;
use pkcs8::{spki::AlgorithmIdentifier, PrivateKeyInfo};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, Sequence)]
/// CompositeSignaturePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
/// CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
struct CompositeSigKemPrivateKey<'a> {
    pq_sk: PrivateKeyInfo<'a>,
    trad_sk: PrivateKeyInfo<'a>,
}

/// A private key for a composite DSA / KEM
#[derive(Zeroize)]
pub struct CompositePrivateKey {
    /// The private key for the post-quantum DSA / KEM
    pq_sk_der: Vec<u8>,
    /// The private key for the traditional DSA / KEM
    trad_sk_der: Vec<u8>,
    /// The OID for the composite DSA / KEM
    oid: String,
}

impl CompositePrivateKey {
    /// Create a new composite DSA / KEM private key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite DSA / KEM
    /// * `pq_sk` - The private key for the post-quantum DSA / KEM
    /// * `trad_sk` - The private key for the traditional DSA / KEM
    ///
    /// # Returns
    ///
    /// A new composite DSA / KEM private key
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

    /// Get the OID for the composite DSA / KEM
    ///
    /// # Returns
    ///
    /// The OID for the composite DSA / KEM
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the private key for the post-quantum DSA / KEM
    ///
    /// # Returns
    ///
    /// The private key for the post-quantum DSA / KEM
    pub fn get_pq_sk(&self) -> Result<PrivateKeyInfo<'_>> {
        Ok(PrivateKeyInfo::from_der(self.pq_sk_der.as_slice())?)
    }

    /// Get the private key for the traditional DSA / KEM
    ///
    /// # Returns
    ///
    /// The private key for the traditional DSA / KEM
    pub fn get_trad_sk(&self) -> Result<PrivateKeyInfo<'_>> {
        Ok(PrivateKeyInfo::from_der(self.trad_sk_der.as_slice())?)
    }

    /// Create a new composite private key from a PEM-encoded private key
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM-encoded private key
    ///
    /// # Returns
    ///
    /// A new composite private key
    pub fn from_pem(pem: &str) -> Result<Self> {
        let parsed = pem::parse(pem)?;
        // Should be -----BEGIN PRIVATE KEY-----
        if parsed.tag() != "PRIVATE KEY" {
            return Err("Invalid PEM tag".into());
        }

        CompositePrivateKey::from_der(parsed.contents())
    }

    /// Create a new composite private key from a DER-encoded private key
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded private key
    ///
    /// # Returns
    ///
    /// A new composite private key
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let priv_key_info = PrivateKeyInfo::from_der(der)?;
        let composite_alg_oid = priv_key_info.algorithm.oid.to_string();
        let key_data = CompositeSigKemPrivateKey::from_der(priv_key_info.private_key).unwrap();
        CompositePrivateKey::new(&composite_alg_oid, &key_data.pq_sk, &key_data.trad_sk)
    }

    /// Serialize the composite private key to a PEM-encoded private key
    ///
    /// # Returns
    ///
    /// The PEM-encoded private key
    pub fn to_pem(&self) -> Result<String> {
        let comp = CompositeSigKemPrivateKey {
            pq_sk: self.get_pq_sk()?,
            trad_sk: self.get_trad_sk()?,
        };

        let priv_key_info = PrivateKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: self.oid.parse().unwrap(),
                parameters: None,
            },
            private_key: &comp.to_der()?,
            public_key: None,
        };
        Ok(priv_key_info.to_pem(pkcs8::LineEnding::LF)?)
    }

    /// Serialize the composite private key to a DER-encoded private key
    ///
    /// # Returns
    ///
    /// The DER-encoded private key
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let comp = CompositeSigKemPrivateKey {
            pq_sk: self.get_pq_sk()?,
            trad_sk: self.get_trad_sk()?,
        };

        let priv_key_info = PrivateKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: self.oid.parse().unwrap(),
                parameters: None,
            },
            private_key: &comp.to_der()?,
            public_key: None,
        };
        Ok(priv_key_info.to_der()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::dsa::common::dsa_type::DsaType;

    use super::*;
    use crate::dsa::common::config::oids::Oid;

    #[test]
    fn test_composite_private_key() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_sk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let sk = CompositePrivateKey::from_pem(pem).unwrap();

        let oid = sk.get_oid();
        assert_eq!(oid, DsaType::MlDsa44EcdsaP256SHA256.get_oid());

        let pem2 = sk.to_pem().unwrap();
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
