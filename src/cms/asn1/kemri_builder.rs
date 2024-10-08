use crate::{cms::cms_util::CmsUtil, wrap::api::WrapManager, wrap::common::wrap_trait::Wrap};
use cms::{
    builder::{RecipientInfoBuilder, RecipientInfoType},
    content_info::CmsVersion,
    enveloped_data::{OtherRecipientInfo, RecipientIdentifier, RecipientInfo, UserKeyingMaterial},
};
use der::{asn1::OctetString, Any, Decode, Encode};
use spki::{AlgorithmIdentifier, ObjectIdentifier};

use crate::{
    kem::{common::kem_trait::Kem, kem_manager::KemManager},
    Certificate,
};

const ID_ORI_KEM: &str = "1.2.840.113549.1.9.16.13.3";

use super::kemri::KemRecipientInfo;

type Result<T> = std::result::Result<T, cms::builder::Error>;
use cms::builder::Error;

pub struct KemRecipientInfoBuilder {
    pub cert: Certificate,
    pub kem: KemManager,
    pub kdf_oid: String,
    pub wrap_oid: String,
    pub ukm: Option<UserKeyingMaterial>,
}

impl KemRecipientInfoBuilder {
    pub fn new(
        cert: &Certificate,
        kem: KemManager,
        kdf_oid: String,
        wrap_oid: String,
        ukm: Option<UserKeyingMaterial>,
    ) -> Self {
        Self {
            cert: cert.clone(),
            kem,
            kdf_oid,
            wrap_oid,
            ukm,
        }
    }
}

impl RecipientInfoBuilder for KemRecipientInfoBuilder {
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> cms::builder::RecipientInfoType {
        RecipientInfoType::Ori
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> cms::content_info::CmsVersion {
        CmsVersion::V3
    }

    fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        let pk = self
            .cert
            .get_public_key()
            .map_err(|_| Error::Builder("Error getting public key from cert".to_string()))?;
        let pk = pk.get_key();
        let (ss, kem_ct) = self
            .kem
            .encap(pk)
            .map_err(|_| Error::Builder("Error encapsulating key".to_string()))?;
        let wrap_man = WrapManager::new_from_oid(&self.wrap_oid)
            .map_err(|_| Error::Builder("Error creating wrap manager".to_string()))?;

        let kek_length = wrap_man.get_wrap_info().key_length;

        let kek = CmsUtil::get_kek(
            &ss,
            &self.wrap_oid,
            &self.kdf_oid,
            kek_length,
            self.ukm.clone(),
        )
        .map_err(|_| Error::Builder("Error getting KEK".to_string()))?;

        let wrapped_key = wrap_man
            .wrap(&kek, content_encryption_key)
            .map_err(|_| Error::Builder("Error wrapping key".to_string()))?;

        let skid = self.cert.get_subject_key_identifier().map_err(|_| {
            Error::Builder("Error getting subject key identifier from cert".to_string())
        })?;
        let rid = RecipientIdentifier::SubjectKeyIdentifier(skid);

        let kem_oid = self.kem.get_kem_info().oid;
        let kem_oid: ObjectIdentifier = kem_oid
            .parse()
            .map_err(|_| Error::Builder("Error parsing KEM OID".to_string()))?;

        let kem_ct = OctetString::new(kem_ct)
            .map_err(|_| Error::Builder("Error converting KEM CT to OctetString".to_string()))?;

        let kdf_oid: ObjectIdentifier = self
            .kdf_oid
            .parse()
            .map_err(|_| Error::Builder("Error parsing KDF OID".to_string()))?;

        let wrap_oid: ObjectIdentifier = self
            .wrap_oid
            .parse()
            .map_err(|_| Error::Builder("Error parsing wrap OID".to_string()))?;

        let kemri = KemRecipientInfo {
            version: CmsVersion::V0,
            rid,
            kem: AlgorithmIdentifier {
                oid: kem_oid,
                parameters: None, // Params are absent for ML-KEM algorithms per draft-ietf-lamps-cms-kyber-01 section 10.2.1
            },
            kem_ct,
            kdf: AlgorithmIdentifier {
                oid: kdf_oid,
                parameters: None, // Params are absent for AES key wrap algorithms per RFC 8619 section 3
            },
            kek_length,
            ukm: self.ukm.clone(),
            wrap: AlgorithmIdentifier {
                oid: wrap_oid,
                parameters: None,
            },
            encrypted_key: OctetString::new(wrapped_key)?,
        };

        let oid_kem: ObjectIdentifier = ID_ORI_KEM
            .parse()
            .map_err(|_| Error::Builder("Error parsing KEM ORI OID".to_string()))?;

        let der = kemri.to_der()?;
        let ori_value = Any::from_der(&der)?;
        let ori = OtherRecipientInfo {
            ori_type: oid_kem,
            ori_value,
        };

        Ok(RecipientInfo::Ori(ori))
    }
}
