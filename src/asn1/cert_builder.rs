use der::asn1::BitString;
use der::referenced::OwnedToRef;
use std::error;

use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::dsa_manager::DsaManager;
use der::Encode;
use pkcs8::spki::AlgorithmIdentifier;
use pkcs8::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::time::Validity;
use x509_cert::Certificate;
use x509_cert::{ext::Extensions, serial_number::SerialNumber, TbsCertificate, Version};

use super::raw_private_key::RawPrivateKey;
use super::raw_public_key::RawPublicKey;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

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
    // #[cfg(feature = "hazmat")]
    // /// Opt-out of the default extensions
    // Manual {
    //     /// issuer   Name,
    //     /// represents the name signing the certificate
    //     /// A `None` will make it a self-signed certificate
    //     issuer: Option<Name>,
    // },
}

impl Profile {
    fn get_issuer(&self, subject: &Name) -> Name {
        match self {
            Profile::Root => subject.clone(),
            Profile::SubCA { issuer, .. } => issuer.clone(),
            Profile::Leaf { issuer, .. } => issuer.clone(),
            // #[cfg(feature = "hazmat")]
            // Profile::Manual { issuer, .. } => issuer.as_ref().unwrap_or(subject).clone(),
        }
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<Vec<Extension>> {
        // #[cfg(feature = "hazmat")]
        // // User opted out of default extensions set.
        // if let Profile::Manual { .. } = self {
        //     return Ok(vec::Vec::default());
        // }

        let mut extensions: Vec<Extension> = Vec::new();

        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(&tbs.subject, &extensions)?);

        // Build Authority Key Identifier
        match self {
            Profile::Root => {}
            _ => {
                extensions.push(
                    AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                        .to_extension(&tbs.subject, &extensions)?,
                );
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

pub struct CertificateBuilder {
    tbs: TbsCertificate,
    extensions: Extensions,
    profile: Profile,
    signer: DsaManager,
    signer_pk: RawPublicKey,
    signer_sk: RawPrivateKey,
}

impl CertificateBuilder {
    /// Creates a new certificate builder
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Profile,
        serial_number: SerialNumber,
        validity: Validity,
        subject: Name,
        subject_public_key_info: RawPublicKey,
        signer: DsaManager,
        signer_pk: RawPublicKey,
        signer_sk: RawPrivateKey,
    ) -> Result<Self> {
        // The signer's oid must match the public key's oid
        if signer.get_dsa_info().oid != subject_public_key_info.get_oid() {
            return Err("Signer's OID does not match the public key's OID".into());
        }

        let signature_alg = AlgorithmIdentifier {
            oid: pkcs8::ObjectIdentifier::new(subject_public_key_info.get_oid())?,
            parameters: None,
        };

        let issuer = profile.get_issuer(&subject);

        let spki = SubjectPublicKeyInfo::from_key(subject_public_key_info)?;

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: signature_alg,
            issuer,
            validity,
            subject,
            subject_public_key_info: spki,
            extensions: None,

            // We will not generate unique identifier because as per RFC5280 Section 4.1.2.8:
            //   CAs conforming to this profile MUST NOT generate
            //   certificates with unique identifiers.
            //
            // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.8
            issuer_unique_id: None,
            subject_unique_id: None,
        };

        let extensions = Vec::new();

        Ok(Self {
            tbs,
            extensions,
            profile,
            signer,
            signer_pk,
            signer_sk,
        })
    }

    /// Add an extension to this certificate
    ///
    /// Extensions need to implement [`AsExtension`], examples may be found in
    /// in [`AsExtension` documentation](../ext/trait.AsExtension.html#examples) or
    /// [the implementors](../ext/trait.AsExtension.html#implementors).
    pub fn add_extension<E: AsExtension>(&mut self, extension: &E) -> Result<()> {
        let ext = extension.to_extension(&self.tbs.subject, &self.extensions)?;
        self.extensions.push(ext);

        Ok(())
    }

    pub fn build(&mut self) -> Result<Certificate> {
        // Create signer's public key info
        let signer_pub = SubjectPublicKeyInfo::from_key(self.signer_pk.clone())?;

        let mut default_extensions = self.profile.build_extensions(
            self.tbs.subject_public_key_info.owned_to_ref(),
            signer_pub.owned_to_ref(),
            &self.tbs,
        )?;

        self.extensions.append(&mut default_extensions);

        if !self.extensions.is_empty() {
            self.tbs.extensions = Some(self.extensions.clone());
        }

        let tbs_der = self.tbs.to_der()?;
        let signature = self.signer.sign(self.signer_sk.get_key(), &tbs_der)?;

        let signature = BitString::new(0, signature)?;

        Ok(Certificate {
            tbs_certificate: self.tbs.clone(),
            signature_algorithm: self.tbs.signature.clone(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use der::{DecodePem, EncodePem};
    use pkcs8::LineEnding;

    use super::*;
    use crate::{
        asn1::{
            composite_private_key::CompositePrivateKey, composite_public_key::CompositePublicKey,
        },
        dsa::common::dsa_type::DsaType,
    };

    #[test]
    fn test_certificate_builder() {
        let mut dsa = DsaManager::new(DsaType::MlDsa44EcdsaP256SHA256);
        let (pk, sk) = dsa.key_gen().unwrap();

        let comp_pk = CompositePublicKey::from_der(&pk).unwrap();
        let comp_sk = CompositePrivateKey::from_der(&sk).unwrap();

        let raw_pk = RawPublicKey::from_composite_public_key(&comp_pk).unwrap();
        let raw_sk = RawPrivateKey::from_composite_private_key(&comp_sk).unwrap();

        let profile = Profile::Root;
        let serial_number = SerialNumber::from(42u32);
        let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
        let subject = Name::from_str("CN=SSAI,O=SSAI,C=SG").unwrap();

        let mut builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            raw_pk.clone(),
            dsa.clone(),
            raw_pk,
            raw_sk,
        )
        .unwrap();

        let cert = builder.build().unwrap();

        let pem = cert.to_pem(LineEnding::LF).unwrap();

        let cert = Certificate::from_pem(&pem.as_bytes()).unwrap();

        let is_verified = dsa
            .verify(
                &comp_pk.to_der().unwrap(),
                &cert.tbs_certificate.to_der().unwrap(),
                &cert.signature.raw_bytes(),
            )
            .unwrap();
        assert!(is_verified);
    }
}
