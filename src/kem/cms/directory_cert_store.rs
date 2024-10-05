use cms::enveloped_data::RecipientIdentifier;
use std::fs;
use std::path::Path;

use crate::kem::cms::cert_store_trait::CertificateStore;
use crate::{Certificate, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

/// Directory-based certificate store.
///
/// This is a simple implementation of the `CertificateStore` trait that
/// uses a directory of certificates.
///
/// The directory should contain the certificates of the trust anchors, sub-CAs,
/// and end-entities. The certificates should be in DER or PEM format.
///
/// This store will attempt to resolve the recipient's certificate to a
/// trust anchor certificate by following the certificate chain.
///
/// The TA certificates should be self-signed. The EE certificates should be
/// signed by a sub-CA or a TA.
///
/// sub-CA certs should be signed by a TA or another sub-CA.
///
/// This store does not support CRLs or OCSP and does not check the path
/// length constraints. It is meant for testing and educational purposes only.
///
/// For a real-world application, use you can write your own authenticator that
/// implements the `CertificateStore` trait and can check the CRLs, OCSP,
/// and path length constraints.
pub struct DirectoryCertificateStore {
    ta_certificates: Vec<Certificate>,
    ee_certificates: Vec<Certificate>,
}

impl DirectoryCertificateStore {
    pub fn new(path: &str) -> Result<DirectoryCertificateStore> {
        let mut ta_certificates = vec![];
        let mut ee_certificates = vec![];

        let dir_path = Path::new(path);

        // Check if the path exists and is a directory
        if dir_path.exists() && dir_path.is_dir() {
            // Iterate through the directory
            for entry in
                fs::read_dir(dir_path).map_err(|_| QuantCryptError::InvalidDirectoryPath)?
            {
                let entry = entry.map_err(|_| QuantCryptError::InvalidDirectoryPath)?;
                let path = entry.path();
                let path_str = path.to_str().ok_or(QuantCryptError::InvalidDirectoryPath)?;

                // Try to interpret the file as a certificate
                let cert = Certificate::from_file(path_str);
                if let Ok(cert) = cert {
                    // Check if the certificate is self-signed
                    let is_self_signed = cert.verify_self_signed().map_or(false, |result| result);

                    let is_valid = cert.is_valid().map_or(false, |result| result);

                    // Add the certificate to the appropriate list
                    if is_valid {
                        if is_self_signed {
                            ta_certificates.push(cert);
                        } else {
                            ee_certificates.push(cert);
                        }
                    }
                }
            }
        } else {
            return Err(QuantCryptError::InvalidDirectoryPath);
        }

        Ok(DirectoryCertificateStore {
            ta_certificates,
            ee_certificates,
        })
    }

    fn find_parent(&self, cert: &Certificate) -> Option<Certificate> {
        // First check if the cert is valid
        if let Ok(is_valid) = cert.is_valid() {
            if !is_valid {
                return None;
            }
        }

        // First look in the trust anchor certificates
        for ta_cert in &self.ta_certificates {
            if let Ok(is_valid) = ta_cert.is_valid() {
                if !is_valid {
                    continue;
                }
            }
            let cert = ta_cert.verify_child(cert).map_or(None, |result| {
                if result {
                    return Some(ta_cert.clone());
                }
                None
            });
            if cert.is_some() {
                return cert;
            }
        }

        // Then look in the end-entity certificates
        for ee_cert in &self.ee_certificates {
            if let Ok(is_valid) = ee_cert.is_valid() {
                if !is_valid {
                    continue;
                }
            }
            let cert = ee_cert.verify_child(cert).map_or(None, |result| {
                if result {
                    return self.find_parent(ee_cert);
                }
                None
            });
            if cert.is_some() {
                return cert;
            }
        }
        None
    }
}

impl CertificateStore for DirectoryCertificateStore {
    fn find(&self, ri: RecipientIdentifier) -> Option<Certificate> {
        match ri {
            cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(issuer) => {
                let serial = issuer.serial_number;
                let issuer = issuer.issuer;
                for cert in self.ee_certificates.clone() {
                    if cert.get_serial_number() == serial && cert.get_issuer() == issuer {
                        // Key encipherment must be enabled
                        if cert.is_key_encipherment_enabled() {
                            // Find the parent certificate
                            let parent = self.find_parent(&cert);
                            if parent.is_some() {
                                return Some(cert);
                            }
                        }
                    }
                }
            }
            cms::enveloped_data::RecipientIdentifier::SubjectKeyIdentifier(ski) => {
                for cert in self.ee_certificates.clone() {
                    if let Ok(cert_ski) = cert.get_subject_key_identifier() {
                        if cert_ski == ski {
                            // Key encipherment must be enabled
                            if cert.is_key_encipherment_enabled() {
                                // Find the parent certificate
                                let parent = self.find_parent(&cert);
                                if parent.is_some() {
                                    return Some(cert);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::builder::Profile;

    use crate::{
        CertValidity, CertificateBuilder, DsaAlgorithm, DsaKeyGenerator, KemAlgorithm,
        KemKeyGenerator,
    };

    use super::*;

    #[test]
    fn test_directory_recipient_auth() {
        let dir_path = "test/data/chain";

        // Create some certificates
        let (ta_pk, ta_sk) = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44)
            .generate()
            .unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            None,
            CertValidity::new(None, "2030-01-01T00:00:00Z").unwrap(),
            "CN=example.com".to_string(),
            ta_pk.clone(),
            &ta_sk,
        )
        .unwrap()
        .build()
        .unwrap();

        // Write the certificate to a file
        let cert_path = format!(
            "{}/{}_{}_ta.der",
            dir_path,
            cert.get_public_key_oid(),
            cert.get_public_key_oid_friendly_name()
        );
        cert.to_der_file(&cert_path).unwrap();

        // Create a sub-CA certificate
        let (sub_pk, sub_sk) = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44)
            .generate()
            .unwrap();
        let cert_sub = CertificateBuilder::new(
            Profile::SubCA {
                issuer: cert.get_subject(),
                path_len_constraint: None,
            },
            None,
            CertValidity::new(None, "2030-01-01T00:00:00Z").unwrap(),
            "CN=sub.example.com".to_string(),
            sub_pk.clone(),
            &ta_sk,
        )
        .unwrap()
        .build()
        .unwrap();

        // Write the certificate to a file
        let cert_path = format!(
            "{}/{}_{}_sub.der",
            dir_path,
            cert_sub.get_public_key_oid(),
            cert_sub.get_public_key_oid_friendly_name()
        );
        cert_sub.to_pem_file(&cert_path).unwrap();

        // Create an end-entity certificate
        let (ee_pk, _) = KemKeyGenerator::new(KemAlgorithm::MlKem512)
            .generate()
            .unwrap();
        let cert_ee = CertificateBuilder::new(
            Profile::Leaf {
                issuer: cert_sub.get_subject(),
                enable_key_agreement: false,
                enable_key_encipherment: true,
            },
            None,
            CertValidity::new(None, "2030-01-01T00:00:00Z").unwrap(),
            "CN=ee.sub.example.com".to_string(),
            ee_pk,
            &sub_sk,
        )
        .unwrap()
        .build()
        .unwrap();

        // Write the certificate to a file
        let cert_path = format!(
            "{}/{}_{}_ee.der",
            dir_path,
            cert_ee.get_public_key_oid(),
            cert_ee.get_public_key_oid_friendly_name()
        );
        cert_ee.to_der_file(&cert_path).unwrap();

        let auth = DirectoryCertificateStore::new(dir_path).unwrap();

        // Test finding the trust anchor certificate
        let ta_ri = RecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: cert.get_issuer(),
            serial_number: cert.get_serial_number(),
        });

        let ta_cert = auth.find(ta_ri);
        // It should not be found because the key encipherment is not enabled
        assert!(ta_cert.is_none());

        // Test finding the TA certificate, by subject key identifier
        let ta_ri =
            RecipientIdentifier::SubjectKeyIdentifier(cert.get_subject_key_identifier().unwrap());
        let ta_cert = auth.find(ta_ri);
        assert!(ta_cert.is_none());

        // Test finding the sub-CA certificate
        let sub_ri = RecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: cert_sub.get_issuer(),
            serial_number: cert_sub.get_serial_number(),
        });

        let sub_cert = auth.find(sub_ri);
        assert!(sub_cert.is_none());

        // Test finding the sub-CA certificate, by subject key identifier
        let sub_ri = RecipientIdentifier::SubjectKeyIdentifier(
            cert_sub.get_subject_key_identifier().unwrap(),
        );
        let sub_cert = auth.find(sub_ri);
        assert!(sub_cert.is_none());

        // Test finding the end-entity certificate
        let ee_ri = RecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: cert_ee.get_issuer(),
            serial_number: cert_ee.get_serial_number(),
        });

        let ee_cert = auth.find(ee_ri).unwrap();
        assert_eq!(ee_cert.get_subject().to_string(), "CN=ee.sub.example.com");

        // Test finding the end-entity certificate, by subject key identifier
        let ee_ri = RecipientIdentifier::SubjectKeyIdentifier(
            cert_ee.get_subject_key_identifier().unwrap(),
        );
        let ee_cert = auth.find(ee_ri).unwrap();
        assert_eq!(ee_cert.get_subject().to_string(), "CN=ee.sub.example.com");
    }
}
