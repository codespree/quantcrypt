use std::error::Error;
use std::str::FromStr;

use chrono::{DateTime, Datelike, TimeZone, Timelike};
use pkcs8::spki::SubjectPublicKeyInfo;
use rand::RngCore;
use rand_core::OsRng;
use x509_cert::builder::Builder;
pub use x509_cert::builder::Profile;
use x509_cert::ext::AsExtension;
use x509_cert::time::Time;
use x509_cert::{name::Name, serial_number::SerialNumber, time::Validity};

use crate::{errors::QuantCryptError, keys::PrivateKey, keys::PublicKey};

use crate::asn1::certificate::Certificate;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A struct to hold the validity period of a certificate
#[derive(Clone)]
pub struct CertValidity {
    /// The not before date of the certificate
    pub not_before: der::asn1::UtcTime,
    /// The not after date of the certificate
    pub not_after: der::asn1::UtcTime,
}

impl CertValidity {
    fn date_time_to_asn(
        time: &DateTime<chrono::Utc>,
    ) -> std::result::Result<der::asn1::UtcTime, Box<dyn Error>> {
        let dt = der::DateTime::new(
            time.year() as u16,
            time.month() as u8,
            time.day() as u8,
            time.hour() as u8,
            time.minute() as u8,
            time.second() as u8,
        )?;
        let result = der::asn1::UtcTime::from_date_time(dt)?;
        Ok(result)
    }

    /// Create a new CertValidity struct
    ///
    /// # Arguments
    ///
    /// * `not_before` - The not before date of the certificate. If None, the current time is used. The date should be in RFC3339 format.
    /// * `not_after` - The not after date of the certificate. The date should be in RFC3339 format.
    ///
    /// # Returns
    ///
    /// A new CertValidity struct
    ///
    /// # Errors
    ///
    /// `QuantCryptError::InvalidNotBefore` if the not before date is in the future
    /// `QuantCryptError::InvalidNotAfter` if the not after date is in the past
    pub fn new(not_before: Option<&str>, not_after: &str) -> Result<CertValidity> {
        let not_after = DateTime::parse_from_rfc3339(not_after)
            .map_err(|_| QuantCryptError::InvalidNotAfter)?;

        // Set time to UTC
        let not_after = chrono::Utc.from_utc_datetime(&not_after.naive_utc());

        // Check if not after is in the past
        if not_after <= chrono::Utc::now() {
            return Err(QuantCryptError::InvalidNotAfter);
        }

        let not_after_dt = CertValidity::date_time_to_asn(&not_after)
            .map_err(|_| QuantCryptError::InvalidNotAfter)?;

        if let Some(not_before) = not_before {
            let not_before = DateTime::parse_from_rfc3339(not_before)
                .map_err(|_| QuantCryptError::InvalidNotBefore)?;

            // Set time to UTC
            let not_before = chrono::Utc.from_utc_datetime(&not_before.naive_utc());

            if not_before > not_after {
                return Err(QuantCryptError::InvalidNotBefore);
            }

            let not_before_dt = CertValidity::date_time_to_asn(&not_before)
                .map_err(|_| QuantCryptError::InvalidNotBefore)?;

            Ok(CertValidity {
                not_before: not_before_dt,
                not_after: not_after_dt,
            })
        } else {
            // Use now as not_before
            let not_before = chrono::Utc::now();

            if not_before > not_after {
                return Err(QuantCryptError::InvalidNotAfter);
            }

            let not_before_dt = CertValidity::date_time_to_asn(&not_before)
                .map_err(|_| QuantCryptError::InvalidNotBefore)?;

            Ok(CertValidity {
                not_before: not_before_dt,
                not_after: not_after_dt,
            })
        }
    }
}

/// A builder for creating X.509 certificates
///
/// # Example:
/// ```
/// use quantcrypt::certificates::CertificateBuilder;
/// use quantcrypt::dsas::DsaAlgorithm;
/// use quantcrypt::kems::KemAlgorithm;
/// use quantcrypt::certificates::Profile;
/// use quantcrypt::dsas::DsaKeyGenerator;
/// use quantcrypt::kems::KemKeyGenerator;
/// use quantcrypt::certificates::CertValidity;
///
/// // Create a TA key pair
/// let (pk_root, sk_root) = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44).generate().unwrap();
///
/// let profile = Profile::Root;
/// let serial_no = None; // This will generate a random serial number
/// let validity = CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(); // Not before is now
/// let subject = "CN=example.com".to_string();
/// let cert_public_key = pk_root.clone();
/// let signer = &sk_root;
///
/// // Create the TA certificate builder
/// let builder = CertificateBuilder::new(
///   profile,
///   serial_no,
///   validity.clone(),
///   subject.clone(),
///   cert_public_key,
///   signer).unwrap();
/// let cert_root = builder.build().unwrap();
/// assert!(cert_root.verify_self_signed().unwrap());
/// // Create a leaf (EE) key pair for KEM
/// let (pk_kem, sk_kem) = KemKeyGenerator::new(KemAlgorithm::MlKem512).generate().unwrap();
/// let builder = CertificateBuilder::new(Profile::Leaf {
///   issuer: cert_root.get_subject(),
///   enable_key_agreement: false,
///   enable_key_encipherment: true,
/// }, serial_no,
///   validity,
///   subject,
///   pk_kem,
///   signer).unwrap();
/// let cert_kem = builder.build().unwrap();
///
/// // It's not self signed so verification as self signed should fail
/// assert!(!cert_kem.verify_self_signed().unwrap());
///
/// // But it should verify against the root
/// assert!(cert_root.verify_child(&cert_kem).unwrap());
/// ```
pub struct CertificateBuilder<'a> {
    builder: x509_cert::builder::CertificateBuilder<'a, PrivateKey>,
}

impl<'a> CertificateBuilder<'a> {
    /// Create a new certificate builder
    pub fn new(
        profile: Profile,
        serial_number: Option<[u8; 20]>,
        validity: CertValidity,
        subject: String,
        cert_public_key: PublicKey,
        signer: &'a PrivateKey,
    ) -> Result<CertificateBuilder<'a>> {
        let subject = Name::from_str(&subject).map_err(|_| QuantCryptError::BadSubject)?;

        let spki = SubjectPublicKeyInfo::from_key(cert_public_key)
            .map_err(|_| QuantCryptError::BadPublicKey)?;

        let validity = Validity {
            not_before: Time::UtcTime(validity.not_before),
            not_after: Time::UtcTime(validity.not_after),
        };

        let serial_number = if let Some(serial_number) = serial_number {
            SerialNumber::new(&serial_number).map_err(|_| QuantCryptError::BadSerialNumber)?
        } else {
            CertificateBuilder::get_random_serial()?
        };

        let builder = x509_cert::builder::CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            spki,
            signer,
        )
        .map_err(|_| QuantCryptError::Unknown)?;

        Ok(CertificateBuilder { builder })
    }

    pub fn add_extension(&mut self, extension: impl AsExtension) -> Result<&mut Self> {
        self.builder
            .add_extension(&extension)
            .map_err(|_| QuantCryptError::BadExtension)?;

        Ok(self)
    }

    /// Return a random SerialNumber value
    fn get_random_serial() -> Result<SerialNumber> {
        let mut serial = [0u8; 20];
        OsRng.fill_bytes(&mut serial);
        serial[0] = 0x01;
        let serial = SerialNumber::new(&serial).map_err(|_| QuantCryptError::BadSerialNumber)?;
        Ok(serial)
    }

    pub fn build(self) -> Result<Certificate> {
        let cert_inner = self.builder.build().map_err(|_| QuantCryptError::Unknown)?;
        let cert = Certificate::new(cert_inner);
        Ok(cert)
    }
}

#[cfg(test)]
mod test {

    use crate::{dsas::DsaAlgorithm, dsas::DsaKeyGenerator};

    use super::*;

    #[test]
    fn gen_pq_hackathon_artifacts_r4() {
        // Generate R4 artifacts for the hackathon
        let dsa_algs: Vec<DsaAlgorithm> = DsaAlgorithm::all();

        for dsa_alg in dsa_algs.iter() {
            // Use DSA to generate key pair for Trust authority
            let (pk_root, sk_root) = DsaKeyGenerator::new(*dsa_alg).generate().unwrap();

            let profile = Profile::Root;
            let serial_no = None; // This will generate a random serial number
            let validity = CertValidity::new(None, "2034-01-01T00:00:00Z").unwrap(); // Not before is now
            let subject = "CN=example.com".to_string();
            let cert_public_key = pk_root.clone();
            let signer = &sk_root;

            // Create the TA certificate builder
            // This is a self-signed certificate since cert_public_key and signer are both from the root
            let builder = CertificateBuilder::new(
                profile,
                serial_no,
                validity.clone(),
                subject.clone(),
                cert_public_key,
                signer,
            )
            .unwrap();
            let cert_root = builder.build().unwrap();

            // Verify self-sign cert
            assert!(cert_root.verify_self_signed().unwrap());

            let dsa_alg_name = dsa_alg.to_string();

            let save_dir = "artifacts/r4_certs/non-ipd";

            let file_name = format!("{}/{}-{}_ta.der", save_dir, dsa_alg_name, dsa_alg.get_oid());

            // // Write the self-signed certificate from TA to the temp directory
            cert_root.to_der_file(&file_name).unwrap();
        }
    }
}
