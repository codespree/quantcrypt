use crate::{
    dsa::{common::dsa_trait::Dsa, dsa_manager::DsaManager},
    kem::{common::kem_trait::Kem, kem_manager::KemManager},
    keys::PublicKey,
    oid_mapper::map_to_new_oid,
};
use chrono::{DateTime, Utc};
use cms::enveloped_data::RecipientIdentifier;
use der::{Decode, DecodePem, Encode, EncodePem};
use spki::ObjectIdentifier;
use x509_cert::{
    ext::pkix::{AuthorityKeyIdentifier, KeyUsage, SubjectKeyIdentifier},
    name::RdnSequence,
    serial_number::SerialNumber,
};

use crate::errors::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A certificate
///
/// # Example
/// ```
/// use quantcrypt::certificates::Certificate;
/// let pem_bytes = include_bytes!("../../test/data/2.16.840.1.114027.80.8.1.4_ta.pem");
/// let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
/// let cert = Certificate::from_pem(pem).unwrap();
/// assert!(cert.verify_self_signed().unwrap());
/// ```
#[derive(Clone)]
pub struct Certificate {
    cert: x509_cert::Certificate,
}

impl Certificate {
    /// Create a new certificate
    ///
    /// # Arguments
    ///
    /// * `cert` - The certificate
    ///
    /// # Returns
    ///
    /// The new certificate
    pub(crate) fn new(cert: x509_cert::Certificate) -> Certificate {
        Certificate { cert }
    }

    /// Convert the certificate to DER format bytes
    ///
    /// # Returns
    ///
    /// The DER format bytes
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let result = self
            .cert
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCertificate)?;
        Ok(result)
    }

    /// Convert the certificate to PEM format
    ///
    /// # Returns
    ///
    /// The PEM format certificate as a string
    pub fn to_pem(&self) -> Result<String> {
        let result = self
            .cert
            .to_pem(pkcs8::LineEnding::CR)
            .map_err(|_| QuantCryptError::InvalidCertificate)?;
        Ok(result)
    }

    /// Create a certificate from DER format bytes
    ///
    /// # Arguments
    ///
    /// * `der` - The DER format bytes
    ///
    /// # Returns
    ///
    /// The new certificate
    ///
    /// # Errors
    ///
    /// `CertificateError::InvalidCertificate` will be returned if the certificate is invalid
    pub fn from_der(der: &[u8]) -> Result<Certificate> {
        let mut cert = x509_cert::Certificate::from_der(der)
            .map_err(|_| QuantCryptError::InvalidCertificate)?;
        // Map old OIDs to new OIDs
        let original_oid = cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string();
        let mapped_oid = map_to_new_oid(&original_oid);
        let new_oid: ObjectIdentifier = mapped_oid
            .parse()
            .map_err(|_| QuantCryptError::InvalidCertificate)?;
        cert.tbs_certificate.subject_public_key_info.algorithm.oid = new_oid;
        Ok(Certificate::new(cert))
    }

    /// Create a certificate from a PEM format string
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM format string
    ///
    /// # Returns
    ///
    /// The new certificate
    ///
    /// # Errors
    ///
    /// `CertificateError::InvalidCertificate` will be returned if the certificate is invalid
    pub fn from_pem(pem: &str) -> Result<Certificate> {
        let cert = x509_cert::Certificate::from_pem(pem)
            .map_err(|_| QuantCryptError::InvalidCertificate)?;
        Ok(Certificate::new(cert))
    }

    /// Get the subject name
    ///
    /// # Returns
    ///
    /// The subject name
    pub fn get_subject(&self) -> RdnSequence {
        self.cert.tbs_certificate.subject.clone()
    }

    /// Get the issuer name
    ///
    /// # Returns
    ///
    /// The issuer name
    pub fn get_issuer(&self) -> RdnSequence {
        self.cert.tbs_certificate.issuer.clone()
    }

    /// Get the serial number
    ///
    /// # Returns
    ///
    /// The serial number
    pub fn get_serial_number(&self) -> SerialNumber {
        self.cert.tbs_certificate.serial_number.clone()
    }

    /// Get the subject key identifier
    ///
    /// # Returns
    ///
    /// The subject key identifier
    pub fn get_subject_key_identifier(&self) -> Result<SubjectKeyIdentifier> {
        if let Some(exts) = self.cert.tbs_certificate.extensions.clone() {
            for ext in exts {
                if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER {
                    let ski_raw_bytes = ext.extn_value.as_bytes();
                    let ski = SubjectKeyIdentifier::from_der(ski_raw_bytes)
                        .map_err(|_| QuantCryptError::InvalidCertificate)?;
                    return Ok(ski);
                }
            }
        }
        Err(QuantCryptError::SkidNotFound)
    }

    /// Verify that the certificate is self-signed
    ///
    /// # Returns
    ///
    /// True if the certificate is self-signed, false otherwise
    pub fn verify_self_signed(&self) -> Result<bool> {
        // The certificate must contain basic constraints with cA set to true
        if let Some(exts) = self.cert.tbs_certificate.extensions.clone() {
            for ext in exts {
                if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                    if let Ok(bc) = ext.to_der() {
                        if let Ok(bc) = x509_cert::ext::pkix::BasicConstraints::from_der(&bc) {
                            if bc.ca {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            return Ok(false);
        }

        // The subject and issuer must be the same
        if self.get_subject() != self.get_issuer() {
            return Ok(false);
        }

        let msg = self
            .cert
            .tbs_certificate
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCertificate)?;

        let sig = self.cert.signature.raw_bytes();

        let pk = self.get_public_key()?;

        let result = pk.verify(&msg, sig).unwrap_or(false);

        Ok(result)
    }

    /// Get the public key
    ///
    /// # Returns
    ///
    /// The public key
    pub fn get_public_key(&self) -> Result<PublicKey> {
        let pk_der = self
            .cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCertificate)?;

        let pk = PublicKey::from_der(&pk_der).map_err(|_| QuantCryptError::InvalidCertificate)?;

        Ok(pk)
    }

    /// Verify that the specified certificate is a child of this certificate.
    ///
    /// This checks that the specified child certificate has the same issuer as this certificate's subject,
    /// that the child's Subject Key Identifier matches the Authority Key Identifier of this certificate,
    /// and that the child's signature is valid.
    ///
    /// # Arguments
    ///
    /// * `child` - The child certificate
    ///
    /// # Returns
    ///
    /// True if the child certificate is a child of this certificate, false otherwise
    pub fn verify_child(&self, child: &Certificate) -> Result<bool> {
        // If the child has a different issuer than the parent's subject, it cannot be a child
        if self.get_subject() != child.get_issuer() {
            return Ok(false);
        }

        // If AKID is present in child, it should match the SKID of the parent
        if let Ok(parent_skid) = self.get_subject_key_identifier() {
            if let Some(exts) = child.cert.tbs_certificate.extensions.clone() {
                for ext in exts {
                    if ext.extn_id == const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER {
                        let akid = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                            .map_err(|_| QuantCryptError::InvalidCertificate)?;
                        let akid = if let Some(akid) = akid.key_identifier {
                            akid
                        } else {
                            return Ok(false);
                        };
                        if akid != parent_skid.0 {
                            return Ok(false);
                        }
                    }
                }
            }
        }

        // Verify the signature of the child
        let msg = child
            .cert
            .tbs_certificate
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCertificate)?;
        let sig = child.cert.signature.raw_bytes();
        let pk = self.get_public_key()?;

        let result = pk
            .verify(&msg, sig)
            .map_err(|_| QuantCryptError::InvalidCertificate)?;

        Ok(result)
    }

    /// Load a certificate from the specified file. The file can be in either DER or PEM format.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    ///
    /// # Returns
    ///
    /// The certificate
    pub fn from_file(path: &str) -> Result<Certificate> {
        // Read the contents of the file as bytes
        let contents = std::fs::read(path).map_err(|_| QuantCryptError::FileReadError)?;

        // Try to interpret as DER
        let result = Certificate::from_der(&contents);

        if let Ok(cert) = result {
            Ok(cert)
        } else {
            // Try to interpret as PEM
            let pem =
                std::str::from_utf8(&contents).map_err(|_| QuantCryptError::InvalidCertificate)?;
            if let Ok(cert) = Certificate::from_pem(pem) {
                Ok(cert)
            } else {
                Err(QuantCryptError::InvalidCertificate)
            }
        }
    }

    /// Save the certificate to the specified file in DER format
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    pub fn to_der_file(&self, path: &str) -> Result<()> {
        let der = self.to_der()?;
        std::fs::write(path, der).map_err(|_| QuantCryptError::InvalidCertificate)?;
        Ok(())
    }

    /// Save the certificate to the specified file in PEM format
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    pub fn to_pem_file(&self, path: &str) -> Result<()> {
        let pem = self.to_pem()?;
        std::fs::write(path, pem).map_err(|_| QuantCryptError::InvalidCertificate)?;
        Ok(())
    }

    /// Check if this certificate is identified by the specified recipient identifier
    ///
    /// This could match by either issuer and serial number or subject key identifier
    ///
    /// # Arguments
    ///
    /// * `rid` - The recipient identifier
    ///
    /// # Returns
    ///
    /// True if the certificate is identified by the recipient identifier, false otherwise
    pub fn is_identified_by(&self, rid: &RecipientIdentifier) -> bool {
        match rid {
            cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(issuer) => {
                if self.get_issuer() == issuer.issuer
                    && self.get_serial_number() == issuer.serial_number
                {
                    return true;
                }
            }
            cms::enveloped_data::RecipientIdentifier::SubjectKeyIdentifier(ski) => {
                if let Ok(cert_ski) = self.get_subject_key_identifier() {
                    if cert_ski == *ski {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if this certificate is valid
    ///
    /// # Returns
    ///
    /// True if the certificate is valid, false otherwise
    pub fn is_valid(&self) -> bool {
        // Get the notBefore and notAfter fields as DateTime
        let not_before = self.cert.tbs_certificate.validity.not_before.to_date_time();
        let not_after = self.cert.tbs_certificate.validity.not_after.to_date_time();

        // Interpret the times as UTC
        let not_before: DateTime<Utc> = not_before.to_system_time().into();
        let not_after: DateTime<Utc> = not_after.to_system_time().into();

        // Get the current time
        let now = chrono::Utc::now();

        // Check if the current time is within the validity period
        let result = now >= not_before && now <= not_after;

        // Certificate sig oid must match the expected sig oid
        let oid = self.cert.signature_algorithm.oid;
        let expected_oid = self.cert.tbs_certificate.signature.oid;
        if oid != expected_oid {
            return false;
        }

        result
    }

    /// Check if key encipherment is enabled
    ///
    /// # Returns
    ///
    /// True if key encipherment is enabled, false otherwise
    pub fn is_key_encipherment_enabled(&self) -> bool {
        if let Some(exts) = self.cert.tbs_certificate.extensions.clone() {
            for ext in exts {
                if ext.extn_id == const_oid::db::rfc5280::ID_CE_KEY_USAGE {
                    if let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes()) {
                        return ku.key_encipherment();
                    }
                }
            }
        }
        false
    }

    /// Get the OID of algorithm used for the public key
    ///
    /// # Returns
    ///
    /// The OID of the algorithm used for the public key
    pub fn get_public_key_oid(&self) -> String {
        self.cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string()
    }

    /// Get the OID of algorithm used for the signature
    ///
    /// # Returns
    ///
    /// The OID of the algorithm used for the signature
    pub fn get_signature_oid(&self) -> String {
        self.cert.tbs_certificate.signature.oid.to_string()
    }

    /// Get the friendly name of the algorithm used for the public key
    ///
    /// # Returns
    ///
    /// The friendly name of the algorithm used for the public key
    pub fn get_public_key_oid_friendly_name(&self) -> String {
        let oid = self.get_public_key_oid();
        if let Ok(man) = DsaManager::new_from_oid(&oid) {
            let info = man.get_dsa_info();
            format!("{:?}", info.dsa_type)
        } else if let Ok(man) = KemManager::new_from_oid(&oid) {
            let info = man.get_kem_info();
            format!("{:?}", info.kem_type)
        } else {
            "Unknown".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{certificates::CertValidity, certificates::Certificate};

    #[test]
    fn test_ml_dsa44_ecdsa_p256_sha256_self_signed_cert() {
        let pem_bytes = include_bytes!("../../test/data/2.16.840.1.114027.80.8.1.4_ta.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_ml_dsa_44_rsa2048_pss_sha256_self_signed_cert() {
        let pem_bytes = include_bytes!("../../test/data/2.16.840.1.114027.80.8.1.1_ta.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(&pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_ml_dsa_44_rsa2048_pkcs15_sha256_self_signed_cert() {
        let pem_bytes = include_bytes!("../../test/data/2.16.840.1.114027.80.8.1.2_ta.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(&pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_dsa_kem() {
        let pem_bytes = include_bytes!("../../test/data/2.16.840.1.101.3.4.3.17_ta.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(&pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());

        let child_pem_bytes = include_bytes!("../../test/data/2.16.840.1.101.3.4.4.1_ee.pem");
        let child_pem = std::str::from_utf8(child_pem_bytes).unwrap().trim();
        let child_cert = Certificate::from_pem(&child_pem).unwrap();

        assert!(cert.verify_child(&child_cert).unwrap());
    }

    #[test]
    fn test_akid_skid() {
        // First generate a TA cert
        let (pk, sk) = crate::dsas::DsaKeyGenerator::new(crate::dsas::DsaAlgorithm::MlDsa44)
            .generate()
            .unwrap();

        let validity = CertValidity::new(None, "2025-01-01T00:00:00Z").unwrap();

        let cert = crate::certificates::CertificateBuilder::new(
            crate::certificates::Profile::Root,
            None,
            validity,
            "CN=example.com".to_string(),
            pk,
            &sk,
        )
        .unwrap()
        .build()
        .unwrap();

        // Next generate a leaf KEM cert
        let (pk_kem, _) = crate::kems::KemKeyGenerator::new(crate::kems::KemAlgorithm::MlKem512)
            .generate()
            .unwrap();

        let validity = CertValidity::new(None, "2025-01-01T00:00:00Z").unwrap();

        let cert_kem = crate::certificates::CertificateBuilder::new(
            crate::certificates::Profile::Leaf {
                issuer: cert.get_subject(),
                enable_key_agreement: false,
                enable_key_encipherment: true,
            },
            None,
            validity,
            "CN=example.com".to_string(),
            pk_kem,
            &sk,
        )
        .unwrap()
        .build()
        .unwrap();

        assert!(!cert_kem.verify_self_signed().unwrap());
        assert!(cert.verify_child(&cert_kem).unwrap());
    }

    #[test]
    fn test_certificate_expiry() {
        // Get now plus 2 secs as UTC String
        let now = chrono::Utc::now();
        let not_before = now + chrono::Duration::seconds(2);
        let not_after = now + chrono::Duration::seconds(5);

        let validity =
            CertValidity::new(Some(&not_before.to_rfc3339()), &not_after.to_rfc3339()).unwrap();

        let (pk, sk) = crate::dsas::DsaKeyGenerator::new(crate::dsas::DsaAlgorithm::MlDsa44)
            .generate()
            .unwrap();
        let cert = crate::certificates::CertificateBuilder::new(
            crate::certificates::Profile::Root,
            None,
            validity,
            "CN=example.com".to_string(),
            pk,
            &sk,
        )
        .unwrap()
        .build()
        .unwrap();
        assert!(!cert.is_valid());
        // sleep for 1 second
        std::thread::sleep(std::time::Duration::from_secs(3));
        assert!(cert.is_valid());
        // sleep for 3 seconds
        std::thread::sleep(std::time::Duration::from_secs(5));
        assert!(!cert.is_valid());
    }
}
