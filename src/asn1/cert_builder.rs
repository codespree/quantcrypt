use std::error::Error;
use std::str::FromStr;

use chrono::{DateTime, Datelike, TimeZone, Timelike};
use der::asn1::BitString;
use der::{referenced::OwnedToRef, Encode};
use pkcs8::spki::{
    AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef,
};
use x509_cert::ext::AsExtension;
use x509_cert::time::Time;
use x509_cert::{
    ext::{
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    TbsCertificate, Version,
};

use crate::{errors::QuantCryptError, PrivateKey, PublicKey};

use crate::asn1::certificate::Certificate;

type Result<T> = std::result::Result<T, QuantCryptError>;

pub struct CertValidity {
    pub not_before: der::asn1::UtcTime,
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

    pub fn new(not_before: &Option<String>, not_after: &str) -> Result<CertValidity> {
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

/// The type of certificate to build
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Build a root CA certificate
    Root,
    /// Build an intermediate sub CA certificate
    SubCA {
        /// issuer   Name,
        /// represents the name signing the certificate
        issuer: Name,
        /// pathLenConstraint       INTEGER (0..MAX) OPTIONAL
        /// BasicConstraints as defined in [RFC 5280 Section 4.2.1.9].
        path_len_constraint: Option<u8>,
    },
    /// Build an end certificate
    Leaf {
        /// issuer   Name,
        /// represents the name signing the certificate
        issuer: Name,
        /// should the key agreement flag of KeyUsage be enabled
        enable_key_agreement: bool,
        /// should the key encipherment flag of KeyUsage be enabled
        enable_key_encipherment: bool,
        // should the subject key identifier extension be included
        //
        // From [RFC 5280 Section 4.2.1.2]:
        //  For end entity certificates, subject key identifiers SHOULD be
        //  derived from the public key.  Two common methods for generating key
        //  identifiers from the public key are identified above.
        // #[cfg(feature = "hazmat")]
        // include_subject_key_identifier: bool,
    },
}

impl Profile {
    fn get_issuer(&self, subject: &Name) -> Name {
        match self {
            Profile::Root => subject.clone(),
            Profile::SubCA { issuer, .. } => issuer.clone(),
            Profile::Leaf { issuer, .. } => issuer.clone(),
        }
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: Option<SubjectPublicKeyInfoRef<'_>>,
        tbs: &TbsCertificate,
    ) -> std::result::Result<Vec<Extension>, Box<dyn std::error::Error>> {
        let mut extensions: Vec<Extension> = Vec::new();

        // Build Subject Key Identifier
        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(&tbs.subject, &extensions)?);

        // Build Authority Key Identifier
        match self {
            Profile::Root => {}
            _ => {
                if let Some(issuer_spk) = issuer_spk {
                    extensions.push(
                        AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                            .to_extension(&tbs.subject, &extensions)?,
                    );
                }
            }
        }

        // Build Basic Contraints extensions
        extensions.push(match self {
            Profile::Root => BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(&tbs.subject, &extensions)?,
            Profile::SubCA {
                path_len_constraint,
                ..
            } => BasicConstraints {
                ca: true,
                path_len_constraint: *path_len_constraint,
            }
            .to_extension(&tbs.subject, &extensions)?,
            Profile::Leaf { .. } => BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(&tbs.subject, &extensions)?,
            // #[cfg(feature = "hazmat")]
            // Profile::Manual { .. } => unreachable!(),
        });

        // Build Key Usage extension
        match self {
            Profile::Root | Profile::SubCA { .. } => {
                extensions.push(
                    KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                        .to_extension(&tbs.subject, &extensions)?,
                );
            }
            Profile::Leaf {
                enable_key_agreement,
                enable_key_encipherment,
                ..
            } => {
                let mut key_usage = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
                if *enable_key_encipherment {
                    key_usage |= KeyUsages::KeyEncipherment;
                }
                if *enable_key_agreement {
                    key_usage |= KeyUsages::KeyAgreement;
                }

                extensions.push(KeyUsage(key_usage).to_extension(&tbs.subject, &extensions)?);
            } // #[cfg(feature = "hazmat")]
              // Profile::Manual { .. } => unreachable!(),
        }

        Ok(extensions)
    }
}

/// A builder for creating X.509 certificates
///
/// # Example:
/// ```
/// use quantcrypt::CertificateBuilder;
/// use quantcrypt::DsaAlgorithm;
/// use quantcrypt::KemAlgorithm;
/// use quantcrypt::Profile;
/// use quantcrypt::DsaKeyGenerator;
/// use quantcrypt::KemKeyGenerator;
///
/// // Create a TA key pair
/// let (pk_root, sk_root) = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44).generate().unwrap();
/// let serial_no: [u8;20] = [0; 20];
///
/// // Create the TA certificate
/// let cert_root = CertificateBuilder::new(Profile::Root)
///    .set_serial_number(&serial_no)
///    .set_not_after("2025-01-01T00:00:00Z")
///    .set_subject("CN=example.com")
///    .set_public_key(pk_root.clone())
///    .build(&sk_root).unwrap();
/// assert!(cert_root.verify_self_signed().unwrap());
///
/// // Create a leaf key pair for KEM
/// let (pk_kem, sk_kem) = KemKeyGenerator::new(KemAlgorithm::MlKem512).generate().unwrap();
/// let cert_kem = CertificateBuilder::new(Profile::Leaf {
///   issuer: "CN=example.com".parse().unwrap(),
///   enable_key_agreement: false,
///   enable_key_encipherment: true,
/// })
///   .set_serial_number(&serial_no)
///   .set_not_after("2025-01-01T00:00:00Z")
///   .set_subject("CN=ssai.example.com")
///   .set_public_key(pk_kem)
///   .set_signers_public_key(pk_root)
///   .build(&sk_root).unwrap();
///
/// // It's not self signed so verification as self signed should fail
/// assert!(!cert_kem.verify_self_signed().unwrap());
///
/// // But it should verify against the root
/// assert!(cert_root.verify_child(&cert_kem).unwrap());
/// ```
pub struct CertificateBuilder {
    profile: Profile,
    serial_number: Option<[u8; 20]>,
    not_before: Option<String>,
    not_after: Option<String>,
    subject: Option<String>,
    public_key: Option<PublicKey>,
    signers_public_key: Option<PublicKey>,
    extensions: Vec<Extension>,
}

impl CertificateBuilder {
    /// Create a new certificate builder
    pub fn new(profile: Profile) -> CertificateBuilder {
        CertificateBuilder {
            profile,
            serial_number: None,
            not_before: None,
            not_after: None,
            subject: None,
            public_key: None,
            signers_public_key: None,
            extensions: Vec::new(),
        }
    }

    pub fn set_serial_number(&mut self, serial_number: &[u8; 20]) -> &mut Self {
        self.serial_number = Some(*serial_number);
        self
    }

    pub fn set_not_before(&mut self, not_before: &str) -> &mut Self {
        self.not_before = Some(not_before.to_string());
        self
    }

    pub fn set_not_after(&mut self, not_after: &str) -> &mut Self {
        self.not_after = Some(not_after.to_string());
        self
    }

    pub fn set_subject(&mut self, subject: &str) -> &mut Self {
        self.subject = Some(subject.to_string());
        self
    }

    pub fn set_public_key(&mut self, public_key: PublicKey) -> &mut Self {
        self.public_key = Some(public_key);
        self
    }

    pub fn set_signers_public_key(&mut self, signers_public_key: PublicKey) -> &mut Self {
        self.signers_public_key = Some(signers_public_key);
        self
    }

    pub fn add_extension(&mut self, extension: Extension) -> &mut Self {
        self.extensions.push(extension);
        self
    }

    pub fn build(&self, sk: &PrivateKey) -> Result<Certificate> {
        let serial_number = self
            .serial_number
            .ok_or(QuantCryptError::MissingSerialNumber)?;
        let serial_number =
            SerialNumber::new(&serial_number).map_err(|_| QuantCryptError::BadSerialNumber)?;
        let not_after = self
            .not_after
            .as_ref()
            .ok_or(QuantCryptError::MissingNotAfter)?;
        let subject = self
            .subject
            .as_ref()
            .ok_or(QuantCryptError::MissingSubject)?;

        let subject = Name::from_str(subject).map_err(|_| QuantCryptError::BadSubject)?;

        let public_key = self
            .public_key
            .clone()
            .ok_or(QuantCryptError::MissingPublicKey)?;

        let c_validity = CertValidity::new(&self.not_before, not_after)?;

        let validity = Validity {
            not_before: Time::UtcTime(c_validity.not_before),
            not_after: Time::UtcTime(c_validity.not_after),
        };

        let oid =
            ObjectIdentifier::new(sk.get_oid()).map_err(|_| QuantCryptError::BadPrivateKey)?;

        let signature_alg = AlgorithmIdentifier {
            oid,
            parameters: None,
        };

        let spki = SubjectPublicKeyInfo::from_key(public_key)
            .map_err(|_| QuantCryptError::BadPublicKey)?;

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: signature_alg,
            issuer: self.profile.get_issuer(&subject),
            validity,
            subject,
            subject_public_key_info: spki.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(self.extensions.clone()),
        };

        let default_ext = if let Some(signers_public_key) = &self.signers_public_key {
            let issuers_pk = SubjectPublicKeyInfo::from_key(signers_public_key.clone())
                .map_err(|_| QuantCryptError::BadIssuersPublicKey)?;

            self.profile
                .build_extensions(spki.owned_to_ref(), Some(issuers_pk.owned_to_ref()), &tbs)
                .map_err(|_| QuantCryptError::BadPublicKey)?
        } else {
            Vec::new()
        };

        let extensions = if self.extensions.is_empty() {
            default_ext
        } else {
            let mut extensions = self.extensions.clone();
            extensions.extend(default_ext);
            extensions
        };

        let tbs = TbsCertificate {
            extensions: Some(extensions),
            ..tbs
        };

        let tbs_der = tbs.clone().to_der().map_err(|_| QuantCryptError::Unknown)?;

        let signature = sk
            .sign(&tbs_der)
            .map_err(|_| QuantCryptError::BadPrivateKey)?;

        // Convert signature to BitString
        let signature =
            BitString::new(0, signature).map_err(|_| QuantCryptError::InvalidSignature)?;

        Ok(Certificate::new(x509_cert::Certificate {
            tbs_certificate: tbs.clone(),
            signature_algorithm: tbs.signature.clone(),
            signature,
        }))
    }
}
