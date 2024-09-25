// This code is adapted from picky-asn1-x509 crate.
// It is less picky which suits the needs of this project better.
// It may be a conscoius decision to have this crate only deal with composite
// keys and certificates and not with the full X.509 standard.
// Those checks will be added in the future.

use std::error;

use crate::asn1::algorithm_identifier::AlgorithmIdentifier;
use crate::asn1::tbs_certificate::TbsCertificate;
use crate::dsa::asn1::composite_dsa_primitives::CompositeSignatureValue;
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::composite_dsa::CompositeDsaManager;
use der::asn1::BitString;
use der::{Decode, Encode};
use picky_asn1::wrapper::BitStringAsn1;
use picky_asn1_x509::{
    oid, oids, AuthorityKeyIdentifier, BasicConstraints, Extension, ExtensionView,
};
use serde::{Deserialize, Serialize};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// [RFC 5280 #4.1](https://tools.ietf.org/html/rfc5280#section-4.1)
///
/// ```not_rust
/// Certificate  ::=  SEQUENCE  {
///      tbsCertificate       TBSCertificate,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signatureValue       BIT STRING  }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitStringAsn1,
}

impl Certificate {
    fn h_find_extension(&self, key_identifier_oid: &oid::ObjectIdentifier) -> Option<&Extension> {
        (self.tbs_certificate.extensions.0)
            .0
            .iter()
            .find(|ext| ext.extn_id() == key_identifier_oid)
    }

    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        let ext = self.h_find_extension(&oids::subject_key_identifier())?;
        match ext.extn_value() {
            ExtensionView::SubjectKeyIdentifier(ski) => Some(&ski.0),
            _ => None,
        }
    }

    pub fn authority_key_identifier(&self) -> Option<&AuthorityKeyIdentifier> {
        let ext = self.h_find_extension(&oids::authority_key_identifier())?;
        match ext.extn_value() {
            ExtensionView::AuthorityKeyIdentifier(aki) => Some(aki),
            _ => None,
        }
    }

    pub fn basic_constraints(&self) -> Option<&BasicConstraints> {
        let ext = self.h_find_extension(&oids::basic_constraints())?;
        match ext.extn_value() {
            ExtensionView::BasicConstraints(bc) => Some(bc),
            _ => None,
        }
    }

    pub fn extensions(&self) -> &[Extension] {
        (self.tbs_certificate.extensions.0).0.as_slice()
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let certificate: Certificate =
            picky_asn1_der::from_bytes(der).map_err(|e| Box::new(e) as Box<dyn error::Error>)?;
        Ok(certificate)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = picky_asn1_der::to_vec(self)?;
        Ok(der)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem::parse(pem)?;
        // It should be a certificate otherwise it is an error
        if pem.tag() != "CERTIFICATE" {
            Err("Invalid PEM: not a certificate".into())
        } else {
            Certificate::from_der(pem.contents())
        }
    }

    pub fn to_pem(&self) -> Result<String> {
        let der = self.to_der()?;
        let pem = pem::Pem::new("CERTIFICATE", der);
        Ok(pem::encode(&pem))
    }

    pub fn get_signature(&self) -> Result<Vec<u8>> {
        let signature: Vec<u8> = picky_asn1_der::to_vec(&self.signature_value)?;
        let sig_bs = BitString::from_der(&signature)?;
        let raw_sig = sig_bs.as_bytes().unwrap().to_vec();

        // Check if it is a composite signature
        if let Ok(c_sig) = CompositeSignatureValue::from_der(&raw_sig) {
            Ok(c_sig.to_der()?)
        } else {
            Ok(raw_sig)
        }
    }

    pub fn verify_signature(&self, pk: &[u8]) -> Result<bool> {
        let signature = self.get_signature()?;
        let tbs_der = picky_asn1_der::to_vec(&self.tbs_certificate)?;
        let oid: String = self.signature_algorithm.algorithm().0.clone().into();
        let dsa = CompositeDsaManager::new_from_oid(&oid)?;
        dsa.verify(pk, &tbs_der, &signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::asn1::composite_public_key::CompositePublicKey;

    use super::*;

    #[test]
    fn test_certificate_serialization() {
        let pem_bytes =
            include_bytes!("../../test/data/mldsa444_ecdsa_p256_sha256_self_signed.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let certificate = Certificate::from_pem(pem).unwrap();
        let der = certificate.to_der().unwrap();
        let certificate2 = Certificate::from_der(&der).unwrap();
        assert_eq!(certificate, certificate2);
    }

    #[test]
    fn test_certificate_signature_verification() {
        let pem_bytes =
            include_bytes!("../../test/data/mldsa444_ecdsa_p256_sha256_self_signed.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let certificate = Certificate::from_pem(pem).unwrap();

        let pk_bytes = include_bytes!("../../test/data/mldsa444_ecdsa_p256_sha256_pk.pem");
        let pk =
            CompositePublicKey::from_pem(std::str::from_utf8(pk_bytes).unwrap().trim()).unwrap();
        let pk_der = pk.to_der().unwrap();

        assert!(certificate.verify_signature(&pk_der).unwrap());
    }
}
