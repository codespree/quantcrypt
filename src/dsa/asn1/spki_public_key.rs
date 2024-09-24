use std::error;

use der::{
    asn1::{BitString, OctetString},
    Decode, DecodePem, Encode, EncodePem,
};
use der_derive::Sequence;
use pkcs8::spki::AlgorithmIdentifierOwned;
use pkcs8::{ObjectIdentifier, SubjectPublicKeyInfo};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
/// The public key for the composite KEM
struct CompositeDsaSpkiPublicKeyData {
    /// The public key for the post-quantum KEM
    pq_pk: OctetString,
    /// The public key for the traditional KEM
    trad_pk: OctetString,
}

impl CompositeDsaSpkiPublicKeyData {
    pub fn new(pq_pk: &[u8], trad_pk: &[u8]) -> Result<Self> {
        let trad_pk = OctetString::new(trad_pk)?;
        let pq_pk = OctetString::new(pq_pk)?;
        Ok(Self { pq_pk, trad_pk })
    }

    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.trad_pk.as_bytes().to_vec()
    }

    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.pq_pk.as_bytes().to_vec()
    }
}

pub struct CompositeDsaSpkiPublicKey {
    oid: String,
    data: CompositeDsaSpkiPublicKeyData,
}

impl CompositeDsaSpkiPublicKey {
    pub fn new(oid: &str, pq_pk: &[u8], trad_pk: &[u8]) -> Result<Self> {
        let data = CompositeDsaSpkiPublicKeyData::new(pq_pk, trad_pk)?;
        Ok(Self {
            oid: oid.to_string(),
            data,
        })
    }

    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.data.get_trad_pk()
    }

    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.data.get_pq_pk()
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let public_key_info: SubjectPublicKeyInfo<AlgorithmIdentifierOwned, BitString> =
            SubjectPublicKeyInfo::from_pem(pem)?;
        let pk_bytes = public_key_info.subject_public_key.raw_bytes();
        let pk = CompositeDsaSpkiPublicKeyData::from_der(pk_bytes)?;
        Ok(Self {
            oid: public_key_info.algorithm.oid.to_string(),
            data: pk,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let public_key_info: SubjectPublicKeyInfo<AlgorithmIdentifierOwned, BitString> =
            SubjectPublicKeyInfo::from_der(der)?;
        let pk_bytes = public_key_info.subject_public_key.raw_bytes();
        let pk = CompositeDsaSpkiPublicKeyData::from_der(pk_bytes)?;
        Ok(Self {
            oid: public_key_info.algorithm.oid.to_string(),
            data: pk,
        })
    }

    pub fn to_pem(&self) -> Result<String> {
        let pk = self.data.to_der()?;
        let public_key_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new(self.oid.as_str()).unwrap(),
                parameters: None,
            },
            subject_public_key: BitString::new(0, pk)?,
        };
        Ok(public_key_info.to_pem(pkcs8::LineEnding::LF)?)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let pk = self.data.to_der()?;
        let public_key_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new(self.oid.as_str()).unwrap(),
                parameters: None,
            },
            subject_public_key: BitString::new(0, pk)?,
        };
        Ok(public_key_info.to_der()?)
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::dsa_type::DsaType;

    use super::*;

    #[test]
    fn test_composite_dsa_spki_public_key() {
        let pem_bytes = include_bytes!("../../../test/data/mldsa444_ecdsa_p256_sha256_pk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = CompositeDsaSpkiPublicKey::from_pem(pem).unwrap();

        let oid = pk.get_oid();
        assert_eq!(oid, DsaType::MlDsa44EcdsaP256SHA256.get_oid());

        let pem2 = pk.to_pem().unwrap();
        //println!("{}", pem2);
        //let pem_bytes2 = pem2.as_bytes();
        assert_eq!(pem, pem2.trim());

        // Test der serialization
        let der = pk.to_der().unwrap();
        let pk2 = CompositeDsaSpkiPublicKey::from_der(&der).unwrap();

        let oid2 = pk2.get_oid();
        assert_eq!(oid, oid2);

        let der2 = pk2.to_der().unwrap();
        assert_eq!(der, der2);

        assert_eq!(pk.get_trad_pk(), pk2.get_trad_pk());
        assert_eq!(pk.get_pq_pk(), pk2.get_pq_pk());
    }
}
