use chrono::Utc;
use cms::enveloped_data::RecipientIdentifier;
use std::str::FromStr;
use x509_cert::{builder::Profile, name::Name};

use crate::{
    kem::cms::cert_store_trait::CertificateStore, CertValidity, Certificate, CertificateBuilder,
    DsaAlgorithm, DsaKeyGenerator,
};

#[derive(Default)]
pub struct DummyCertificateStore {}
impl DummyCertificateStore {
    pub fn new() -> Self {
        Self {}
    }
}

impl CertificateStore for DummyCertificateStore {
    fn find(&self, _: RecipientIdentifier) -> Option<Certificate> {
        // Just create a dummy certificate for testing
        let (pk, sk) = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44)
            .generate()
            .unwrap();
        let issuer = Name::from_str("CN=dummy.com").unwrap();
        let profile = Profile::Leaf {
            issuer,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        };

        let not_before = Utc::now();
        let not_after = not_before + chrono::Duration::days(365);

        // Convert to ISO8601 format
        let not_after = not_after.to_rfc3339();

        let validity = CertValidity::new(None, &not_after).unwrap();
        let cert_builder =
            CertificateBuilder::new(profile, None, validity, "CN=dummy.com".to_string(), pk, &sk)
                .unwrap();

        Some(cert_builder.build().unwrap())
    }
}
