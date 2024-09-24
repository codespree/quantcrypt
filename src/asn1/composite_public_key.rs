use std::error;

use der::{asn1::BitString, Decode, Encode};
use der_derive::Sequence;
use pem::EncodeConfig;
use pkcs8::ObjectIdentifier;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, Sequence)]
struct CompressedPublicKey {
    pub oid: OidSeq,
    pub data: BitString,
}

#[derive(Debug, Clone, Sequence)]
struct OidSeq {
    pub oid: ObjectIdentifier,
}

#[derive(Debug, Clone, Sequence)]
struct CompositePublicKeyData {
    pq_pk: BitString,
    trad_pk: BitString,
}

pub struct CompositePublicKey {
    oid: String,
    pq_pk: Vec<u8>,
    trad_pk: Vec<u8>,
}

impl CompositePublicKey {
    /// Create a new composite public key
    ///
    /// # Arguments
    ///
    /// * `pq_pk` - The public key for the post-quantum KEM
    /// * `trad_pk` - The public key for the traditional KEM
    ///
    /// # Returns
    ///
    /// A new composite DSA public key
    pub fn new(oid: &str, pq_pk: &[u8], trad_pk: &[u8]) -> Self {
        Self {
            oid: oid.to_string(),
            pq_pk: pq_pk.to_vec(),
            trad_pk: trad_pk.to_vec(),
        }
    }

    /// Get the public key for the traditional DSA
    ///
    /// # Returns
    ///
    /// The public key for the traditional DSA
    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.trad_pk.clone()
    }

    /// Get the public key for the post-quantum DSA
    ///
    /// # Returns
    ///
    /// The public key for the post-quantum DSA
    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.pq_pk.clone()
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem::parse(pem)?;

        if pem.tag() != "PUBLIC KEY" {
            return Err("Invalid PEM tag".into());
        }

        CompositePublicKey::from_der(pem.contents())
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        // Parse as compressed public key
        let compressed_pk: CompressedPublicKey = CompressedPublicKey::from_der(der)?;
        let oid = compressed_pk.oid.oid.to_string();

        let raw_data = if let Some(data) = compressed_pk.data.as_bytes() {
            data
        } else {
            return Err("Invalid public key data".into());
        };

        let comp_pk: CompositePublicKeyData = CompositePublicKeyData::from_der(raw_data)?;
        Ok(CompositePublicKey::new(
            &oid,
            comp_pk.pq_pk.as_bytes().unwrap(),
            comp_pk.trad_pk.as_bytes().unwrap(),
        ))
    }

    pub fn to_pem(&self) -> Result<String> {
        let data = self.to_der()?;
        let encode_conf = EncodeConfig::default().set_line_ending(pem::LineEnding::LF);

        let pem = pem::Pem::new("PUBLIC KEY", data);
        Ok(pem::encode_config(&pem, encode_conf))
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let comp_pk = CompositePublicKeyData {
            pq_pk: BitString::new(0, self.pq_pk.as_slice())?,
            trad_pk: BitString::new(0, self.trad_pk.as_slice())?,
        };

        let raw_data = comp_pk.to_der()?;
        let compressed_pk = CompressedPublicKey {
            oid: OidSeq {
                oid: self.oid.parse().unwrap(),
            },
            data: BitString::new(0, raw_data.as_slice())?,
        };

        Ok(compressed_pk.to_der()?.as_slice().to_vec())
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::dsa_type::DsaType;

    use super::*;

    #[test]
    fn test_composite_public_key() {
        let pem_bytes = include_bytes!("../../test/data/mldsa444_ecdsa_p256_sha256_pk.pem");
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
