use crate::PublicKey;
use der::{Decode, DecodePem, Encode, EncodePem};

use crate::errors::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A certificate
///
/// # Example
/// ```
/// use quantcrypt::Certificate;
/// let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_self_signed.pem");
/// let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
/// let cert = Certificate::from_pem(pem).unwrap();
/// assert!(cert.verify_self_signed().unwrap());
/// ```
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
    pub fn get_subject_name(&self) -> String {
        self.cert.tbs_certificate.subject.to_string()
    }

    /// Verify that the certificate is self-signed
    ///
    /// # Returns
    ///
    /// True if the certificate is self-signed, false otherwise
    pub fn verify_self_signed(&self) -> Result<bool> {
        let msg = self
            .cert
            .tbs_certificate
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCertificate)?;

        let sig = self.cert.signature.raw_bytes();

        let pk = self.get_public_key()?;

        let result = if let Ok(result) = pk.verify(&msg, sig) {
            result
        } else {
            false
        };

        Ok(result)
    }

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

    pub fn verify_child(&self, child: &Certificate) -> Result<bool> {
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
}

#[cfg(test)]
mod tests {
    use crate::Certificate;

    #[test]
    fn test_ml_dsa44_ecdsa_p256_sha256_self_signed_cert() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_self_signed.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_ml_dsa_44_rsa2048_pss_sha256_self_signed_cert() {
        let pem_bytes =
            include_bytes!("../../test/data/mldsa44_rsa2048_pss_sha256_self_signed.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(&pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_ml_dsa_44_rsa2048_pkcs15_sha256_self_signed_cert() {
        let pem_bytes =
            include_bytes!("../../test/data/mldsa44_rsa2048_pkcs15_sha256_self_signed.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let cert = Certificate::from_pem(&pem).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }
}
