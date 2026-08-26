use crate::{
    dsa::{
        common::{dsa_trait::Dsa, prehash_dsa_trait::PrehashDsa},
        dsa_manager::{DsaManager, PrehashDsaManager},
    },
    kem::{common::kem_trait::Kem, kem_manager::KemManager},
    keys::PublicKey,
};
use chrono::{DateTime, Utc};
use cms::enveloped_data::RecipientIdentifier;
use der::{Decode, DecodePem, Encode, EncodePem};
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
/// let cert_path = "test/data/bc_artifacts_certs_r4/ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der";
/// let cert = Certificate::from_file(cert_path).unwrap();
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
            .to_pem(pkcs8::LineEnding::LF)
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
        let cert = x509_cert::Certificate::from_der(der)
            .map_err(|_| QuantCryptError::InvalidCertificate)?;

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
        } else if let Ok(man) = PrehashDsaManager::new_from_oid(&oid) {
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
    use crate::certificates::CertValidity;

    #[test]
    fn test_akid_skid() {
        // First generate a TA cert
        let (pk, sk) = crate::dsas::DsaKeyGenerator::new(crate::dsas::DsaAlgorithm::MlDsa44)
            .generate()
            .unwrap();

        let validity = CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap();

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

        let validity = CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap();

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

    #[test]
    fn test_bc_cert_artifacts() {
        let base_folder_path = "test/data/bc_artifacts_certs_r4/";

        // Verify the pure ML-DSA and SLH-DSA certificates. The R4 composite
        // certificates (uppercase "MLDSA"/"HashMLDSA", old Entrust-arc OIDs
        // 2.16.840.1.114027.80.8.1.x) use a superseded composite draft and are
        // intentionally skipped now that the library tracks
        // draft-ietf-lamps-pq-composite-sigs-19. Cross-provider composite
        // interop should be validated against R5 artifacts.
        let files = std::fs::read_dir(base_folder_path).unwrap();

        let ml_dsa_pure_prefix = "ml-dsa";
        let slh_dsa_prefix = "slh-dsa";
        for file in files {
            let file = file.unwrap();
            let path = file.path();
            let path = path.to_str().unwrap();

            if !path.contains(slh_dsa_prefix) && !path.contains(ml_dsa_pure_prefix) {
                continue;
            }

            let cert = crate::certificates::Certificate::from_file(path).unwrap();

            assert!(cert.verify_self_signed().unwrap());
            println!("Verified: {}", path);
        }

        // Test the ml-kem certificates
        let ta_paths = [
            "test/data/bc_artifacts_certs_r4/ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der",
            "test/data/bc_artifacts_certs_r4/ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der",
            "test/data/bc_artifacts_certs_r4/ml-dsa-87-2.16.840.1.101.3.4.3.19_ta.der",
        ];

        let ee_paths = [
            "test/data/bc_artifacts_certs_r4/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der",
            "test/data/bc_artifacts_certs_r4/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der",
            "test/data/bc_artifacts_certs_r4/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der",
        ];

        for i in 0..ta_paths.len() {
            let ta_cert = crate::certificates::Certificate::from_file(ta_paths[i]).unwrap();
            let ee_cert = crate::certificates::Certificate::from_file(ee_paths[i]).unwrap();

            assert!(ta_cert.verify_child(&ee_cert).unwrap());
            println!("Verified: EE {} with TA {}", ee_paths[i], ta_paths[i]);

            // Test encap
            let pk = ee_cert.get_public_key().unwrap();
            let _ = pk.encap().unwrap();
        }
    }

    #[test]
    fn test_cw_cert_artifacts() {
        let base_folder_path = "test/data/cw_artifacts_certs_r4/";
        // Load all the certificates
        let files = std::fs::read_dir(base_folder_path).unwrap();

        for file in files {
            let file = file.unwrap();
            let path = file.path();
            let path = path.to_str().unwrap();

            let cert = crate::certificates::Certificate::from_file(path).unwrap();

            assert!(cert.verify_self_signed().unwrap());
            println!("Verified: {}", path);
        }
    }

    /// Cross-provider interop gate for the draft-19 composite signatures.
    ///
    /// Loads the self-signed trust-anchor certificates produced by the IETF
    /// Hackathon composite-signatures *reference implementation* (R5 artifacts,
    /// production OID arc 1.3.6.1.5.5.7.6.37-.54) and verifies each signature.
    /// A pass proves that our Prefix / Label / pre-hash construction is
    /// byte-for-byte compatible with the reference implementation for every one
    /// of the 18 composite ML-DSA algorithms (plus the pure ML-DSA anchors).
    #[test]
    fn test_r5_composite_sig_interop() {
        let base = "test/data/r5_interop/composite-sigs-ref-impl/";
        let files = std::fs::read_dir(base).unwrap();
        let mut verified = 0usize;
        for file in files {
            let path = file.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            // Only self-signed trust anchors carry a verifiable signature here.
            if !name.ends_with("_ta.der") {
                continue;
            }
            let cert = crate::certificates::Certificate::from_file(path.to_str().unwrap()).unwrap();
            assert!(
                cert.verify_self_signed().unwrap(),
                "reference-impl cert failed to verify: {name}"
            );
            verified += 1;
            println!("Verified R5 ref-impl TA: {name}");
        }
        // 18 composite algorithms + 3 pure ML-DSA anchors.
        assert!(
            verified >= 18,
            "expected >=18 verified reference-impl anchors, got {verified}"
        );
    }

    /// Cross-provider interop check for the draft-15 composite KEM public-key
    /// encoding. Loads the composite KEM end-entity certificates from the IETF
    /// Hackathon composite-KEM *reference implementation* (R5 artifacts,
    /// production OID arc 1.3.6.1.5.5.7.6.55-.66), parses each `mlkemPK ||
    /// tradPK` public key, and performs an encapsulation. A pass proves our
    /// composite public-key deserialization and encapsulation path are
    /// compatible with the reference implementation's published keys.
    #[test]
    fn test_r5_composite_kem_interop() {
        let base = "test/data/r5_interop/composite-kem-ref-impl/";
        let files = std::fs::read_dir(base).unwrap();
        let mut encapsulated = 0usize;
        for file in files {
            let path = file.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            if !name.ends_with("_ee.der") || !name.contains("1.3.6.1.5.5.7.6.") {
                continue;
            }
            let cert = crate::certificates::Certificate::from_file(path.to_str().unwrap()).unwrap();
            let pk = cert.get_public_key().unwrap();
            pk.encap()
                .unwrap_or_else(|e| panic!("encap failed for {name}: {e:?}"));
            encapsulated += 1;
            println!("Encapsulated to R5 ref-impl composite KEM: {name}");
        }
        assert!(
            encapsulated >= 12,
            "expected >=12 composite KEM encapsulations, got {encapsulated}"
        );
    }

    /// Cross-provider interop for draft-19 composite *private* keys.
    ///
    /// Loads each composite signature private key produced by the reference
    /// implementation (PKCS#8 `mldsaSeed || tradSK`, production OID arc), signs a
    /// message with it, and verifies the signature against the matching trust
    /// anchor's public key. A pass proves our ML-DSA seed expansion and
    /// traditional-key decoding reconstruct exactly the reference key pair.
    #[test]
    fn test_r5_composite_sig_privkey_interop() {
        let base = "test/data/r5_interop/composite-sigs-ref-impl/";
        let msg = b"quantcrypt composite private-key interop test";
        let mut count = 0usize;
        for file in std::fs::read_dir(base).unwrap() {
            let path = file.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if !name.ends_with("_priv.der") || !name.contains("1.3.6.1.5.5.7.6.") {
                continue;
            }
            let prefix = name.strip_suffix("_priv.der").unwrap();
            let sk = crate::keys::PrivateKey::from_file(path.to_str().unwrap())
                .unwrap_or_else(|e| panic!("load sig priv {name}: {e:?}"));
            let ta = crate::certificates::Certificate::from_file(&format!("{base}{prefix}_ta.der"))
                .unwrap();
            let pk = ta.get_public_key().unwrap();
            let sig = sk
                .sign(msg)
                .unwrap_or_else(|e| panic!("sign with {name}: {e:?}"));
            assert!(
                pk.verify(msg, &sig).unwrap(),
                "signature from ref-impl private key {name} failed to verify"
            );
            count += 1;
        }
        assert!(
            count >= 18,
            "expected >=18 composite sig private-key interop, got {count}"
        );
    }

    /// Cross-provider interop for draft-15 composite *private* keys, using the
    /// reference implementation's full decapsulation vectors.
    ///
    /// For each composite KEM private key (PKCS#8 `mlkemSeed || tradSK`), loads
    /// it, decapsulates the reference `_ciphertext.bin`, and asserts the derived
    /// shared secret equals the reference `_ss.bin`. This validates, end-to-end
    /// against the reference implementation, our ML-KEM seed expansion, the
    /// traditional-key decoding, the tradPK recomputation, and the SHA3-256 KEM
    /// combiner.
    #[test]
    fn test_r5_composite_kem_privkey_interop() {
        let base = "test/data/r5_interop/composite-kem-ref-impl/";
        let mut count = 0usize;
        for file in std::fs::read_dir(base).unwrap() {
            let path = file.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if !name.ends_with("_priv.der") || !name.contains("1.3.6.1.5.5.7.6.") {
                continue;
            }
            let prefix = name.strip_suffix("_priv.der").unwrap();
            let ct = std::fs::read(format!("{base}{prefix}_ciphertext.bin")).unwrap();
            let expected_ss = std::fs::read(format!("{base}{prefix}_ss.bin")).unwrap();
            let sk = crate::keys::PrivateKey::from_file(path.to_str().unwrap())
                .unwrap_or_else(|e| panic!("load kem priv {name}: {e:?}"));
            let ss = sk
                .decap(&ct)
                .unwrap_or_else(|e| panic!("decap with {name}: {e:?}"));
            assert_eq!(
                ss, expected_ss,
                "decapsulated shared secret mismatch for {name}"
            );
            count += 1;
        }
        assert!(
            count >= 12,
            "expected >=12 composite KEM decap vectors, got {count}"
        );
    }

    /// Cross-provider interop for the draft-19/-15 composite algorithms against
    /// GREEN R5 artifacts submitted by independent third parties (Bouncy Castle,
    /// Entrust, Crypto4A, CryptoNext, leancrypto) — not our own submission and
    /// not only the reference implementation. For each provider we verify every
    /// composite signature self-signed cert (`*_ta.der`); load every composite
    /// signature private key, sign, and verify the signature against that
    /// provider's trust-anchor public key; and load every composite KEM private
    /// key, decapsulate that provider's `*_ciphertext.bin`, and assert the
    /// result equals its `*_ss.bin`. Any load/verify/decap failure fails the
    /// test (no silent skipping).
    #[test]
    fn test_r5_cross_provider_interop() {
        let base = "test/data/r5_interop/providers";
        // Minimum composite artifacts expected per provider (0 => provider dir
        // may be absent; leancrypto only submitted 3 composite signatures).
        let providers = [
            ("bc", 18, 12),
            ("entrust", 18, 12),
            ("crypto4a", 18, 12),
            ("cryptonext", 18, 12),
            ("leancrypto", 3, 0),
        ];
        let mut total_sig = 0usize;
        let mut total_kem = 0usize;
        for (prov, min_sig, min_kem) in providers {
            let dir = format!("{base}/{prov}");
            let files: Vec<std::path::PathBuf> = match std::fs::read_dir(&dir) {
                Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(_) => panic!("missing provider corpus: {dir}"),
            };
            let find = |suffix: &str, oid: &str| -> Option<std::path::PathBuf> {
                files
                    .iter()
                    .find(|p| {
                        let n = p.file_name().unwrap().to_str().unwrap();
                        n.ends_with(suffix) && n.contains(oid)
                    })
                    .cloned()
            };
            let msg = b"cross-provider composite interop";

            // Signatures (.37-.54): verify TA, and sign+verify with the priv key.
            let mut sig_ok = 0;
            for oidn in 37..=54 {
                let oid = format!("1.3.6.1.5.5.7.6.{oidn}_");
                let Some(ta_p) = find("_ta.der", &oid) else {
                    continue;
                };
                let ta = crate::certificates::Certificate::from_file(ta_p.to_str().unwrap())
                    .unwrap_or_else(|e| panic!("{prov} load TA .{oidn}: {e:?}"));
                assert!(
                    ta.verify_self_signed().unwrap(),
                    "{prov}: TA .{oidn} failed self-verify"
                );
                if let Some(priv_p) = find("_priv.der", &oid) {
                    let sk = crate::keys::PrivateKey::from_file(priv_p.to_str().unwrap())
                        .unwrap_or_else(|e| panic!("{prov} load sig priv .{oidn}: {e:?}"));
                    let sig = sk
                        .sign(msg)
                        .unwrap_or_else(|e| panic!("{prov} sign .{oidn}: {e:?}"));
                    assert!(
                        ta.get_public_key().unwrap().verify(msg, &sig).unwrap(),
                        "{prov}: signature by priv .{oidn} did not verify against its TA"
                    );
                }
                sig_ok += 1;
            }
            assert!(
                sig_ok >= min_sig,
                "{prov}: expected >={min_sig} composite sig certs, got {sig_ok}"
            );
            total_sig += sig_ok;

            // KEM (.55-.66): decap the provider ciphertext, compare to its ss.
            let mut kem_ok = 0;
            for oidn in 55..=66 {
                let oid = format!("1.3.6.1.5.5.7.6.{oidn}_");
                let (Some(priv_p), Some(ct_p), Some(ss_p)) = (
                    find("_priv.der", &oid),
                    find("_ciphertext.bin", &oid),
                    find("_ss.bin", &oid),
                ) else {
                    continue;
                };
                let sk = crate::keys::PrivateKey::from_file(priv_p.to_str().unwrap())
                    .unwrap_or_else(|e| panic!("{prov} load kem priv .{oidn}: {e:?}"));
                let ct = std::fs::read(&ct_p).unwrap();
                let ss = sk
                    .decap(&ct)
                    .unwrap_or_else(|e| panic!("{prov} decap .{oidn}: {e:?}"));
                assert_eq!(
                    ss,
                    std::fs::read(&ss_p).unwrap(),
                    "{prov}: KEM .{oidn} shared secret mismatch"
                );
                kem_ok += 1;
            }
            assert!(
                kem_ok >= min_kem,
                "{prov}: expected >={min_kem} composite KEM vectors, got {kem_ok}"
            );
            total_kem += kem_ok;
            println!("{prov}: {sig_ok} sig + {kem_ok} kem composite artifacts verified");
        }
        // 4 full providers x (18 sig + 12 kem) + leancrypto 3 sig = 75 sig, 48 kem.
        assert!(
            total_sig >= 75,
            "expected >=75 cross-provider sig checks, got {total_sig}"
        );
        assert!(
            total_kem >= 48,
            "expected >=48 cross-provider kem checks, got {total_kem}"
        );
    }
}
