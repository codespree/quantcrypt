use std::error;

use der::{asn1::BitString, Decode, Document, Encode};
use der_derive::Sequence;
use pem::EncodeConfig;
use pkcs8::{spki::AlgorithmIdentifierWithOid, EncodePublicKey};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// PublicKeyInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     PublicKey   BIT STRING
/// }
#[derive(Debug, Clone, Sequence)]
pub struct PublicKeyInfo {
    pub algorithm: AlgorithmIdentifierWithOid,
    pub public_key: BitString,
}

/// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
/// CompositeKEMPublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
#[derive(Debug, Clone, Sequence)]
struct CompositeSigKemPublicKey {
    pq_pk: BitString,
    trad_pk: BitString,
}

#[derive(Debug, Clone)]
/// A public key for a composite DSA / KEM
pub struct CompositePublicKey {
    /// The OID for the composite DSA / KEM
    oid: String,
    /// The public key for the post-quantum DSA / KEM
    pq_pk: Vec<u8>,
    /// The public key for the traditional DSA / KEM
    trad_pk: Vec<u8>,
}

impl CompositePublicKey {
    /// Create a new composite public key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite DSA
    /// * `pq_pk` - The public key for the post-quantum DSA / KEM
    /// * `trad_pk` - The public key for the traditional DSA / KEM
    ///
    /// # Returns
    ///
    /// A new composite DSA / KEM public key
    pub fn new(oid: &str, pq_pk: &[u8], trad_pk: &[u8]) -> Self {
        Self {
            oid: oid.to_string(),
            pq_pk: pq_pk.to_vec(),
            trad_pk: trad_pk.to_vec(),
        }
    }

    /// Get the OID for the composite DSA / KEM
    ///
    /// # Returns
    ///
    /// The OID for the composite DSA / KEM
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the public key for the traditional DSA / KEM
    ///
    /// # Returns
    ///
    /// The public key for the traditional DSA / KEM
    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.trad_pk.clone()
    }

    /// Get the public key for the post-quantum DSA / KEM
    ///
    /// # Returns
    ///
    /// The public key for the post-quantum DSA / KEM
    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.pq_pk.clone()
    }

    /// Create a new composite public key from a PEM-encoded public key
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM-encoded public key
    ///
    /// # Returns
    ///
    /// A new composite public key
    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem::parse(pem)?;

        if pem.tag() != "PUBLIC KEY" {
            return Err("Invalid PEM tag".into());
        }

        CompositePublicKey::from_der(pem.contents())
    }

    /// Create a new composite public key from a DER-encoded public key
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded public key
    ///
    /// # Returns
    ///
    /// A new composite public key
    pub fn from_der(der: &[u8]) -> Result<Self> {
        // Parse as compressed public key
        let public_key_info = PublicKeyInfo::from_der(der)?;
        let oid = public_key_info.algorithm.oid.to_string();

        let raw_data = if let Some(data) = public_key_info.public_key.as_bytes() {
            data
        } else {
            return Err("Invalid public key data".into());
        };

        let comp_pk: CompositeSigKemPublicKey = CompositeSigKemPublicKey::from_der(raw_data)?;
        Ok(CompositePublicKey::new(
            &oid,
            comp_pk.pq_pk.as_bytes().unwrap(),
            comp_pk.trad_pk.as_bytes().unwrap(),
        ))
    }

    /// Encode the composite public key as a PEM-encoded public key
    ///
    /// # Returns
    ///
    /// The PEM-encoded public key
    pub fn to_pem(&self) -> Result<String> {
        let data = self.to_der()?;
        let encode_conf = EncodeConfig::default().set_line_ending(pem::LineEnding::LF);

        let pem = pem::Pem::new("PUBLIC KEY", data);
        Ok(pem::encode_config(&pem, encode_conf))
    }

    /// Encode the composite public key as a DER-encoded public key
    ///
    /// # Returns
    ///
    /// The DER-encoded public key
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let comp_sig_pk = CompositeSigKemPublicKey {
            pq_pk: BitString::new(0, self.pq_pk.as_slice())?,
            trad_pk: BitString::new(0, self.trad_pk.as_slice())?,
        };

        let raw_data = comp_sig_pk.to_der()?;
        let pk_info = PublicKeyInfo {
            algorithm: AlgorithmIdentifierWithOid {
                oid: pkcs8::ObjectIdentifier::new(self.oid.as_str())?,
                parameters: None,
            },
            public_key: BitString::new(0, raw_data.as_slice())?,
        };

        Ok(pk_info.to_der()?.as_slice().to_vec())
    }
}

impl EncodePublicKey for CompositePublicKey {
    fn to_public_key_der(&self) -> std::result::Result<Document, pkcs8::spki::Error> {
        let doc = Document::try_from(self.to_der().unwrap())?;
        Ok(doc)
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::dsa_type::DsaType;

    use super::*;

    #[test]
    fn test_composite_public_key() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_pk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = CompositePublicKey::from_pem(pem).unwrap();

        let der = pk.to_der().unwrap();
        let pk2 = CompositePublicKey::from_der(&der).unwrap();

        assert_eq!(pk.oid, pk2.oid);
        assert_eq!(pk.get_trad_pk(), pk2.get_trad_pk());
        assert_eq!(pk.get_pq_pk(), pk2.get_pq_pk());

        let pem2 = pk2.to_pem().unwrap();
        assert_eq!(pem, pem2.trim());

        let oid = DsaType::MlDsa44EcdsaP256SHA256.get_oid();
        assert_eq!(pk.oid, oid);
    }
}
