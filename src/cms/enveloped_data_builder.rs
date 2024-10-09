use crate::kdf::api::KdfType;
use crate::kdf::common::config::oids::Oid as _;
use crate::kem::common::kem_trait::Kem;
use crate::wrap::api::WrapType;
use crate::wrap::common::config::oids::Oid as _;
use cms::builder::{
    ContentEncryptionAlgorithm, KekRecipientInfoBuilder, KeyAgreeRecipientInfoBuilder,
    KeyTransRecipientInfoBuilder, OtherRecipientInfoBuilder, PasswordRecipientInfoBuilder,
};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{OriginatorInfo, UserKeyingMaterial};
use const_oid::db::rfc5911::{ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA};
use der::{Decode, Encode};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use x509_cert::attr::{Attribute, Attributes};

use crate::{cea::common::cea_type::CeaType, kem::kem_manager, Certificate, QuantCryptError};

use crate::cms::asn1::kemri_builder::KemRecipientInfoBuilder;

use super::asn1::auth_enveloped_data_builder::{
    AuthEnvelopedDataBuilder, ContentEncryptionAlgorithmAead,
};

type Result<T> = std::result::Result<T, QuantCryptError>;

const ALLOWED_CAE_TYPES_ENVELOPED: [CeaType; 3] = [
    CeaType::Aes128CbcPad,
    CeaType::Aes192CbcPad,
    CeaType::Aes256CbcPad,
];

const ALLOWED_CAE_TYPES_AUTH_ENVELOPED: [CeaType; 3] =
    [CeaType::Aes128Gcm, CeaType::Aes192Gcm, CeaType::Aes256Gcm];

pub struct EnvelopedDataBuilder<'a> {
    originator_info: Option<OriginatorInfo>,
    plaintext: Vec<u8>,
    cae_type: CeaType,
    unprotected_attributes: Option<Attributes>,
    auth_attributes: Option<Attributes>,
    kemri_builders: Vec<KemRecipientInfoBuilder>,
    kek_builders: Vec<KekRecipientInfoBuilder>,
    ktri_builders: Vec<KeyTransRecipientInfoBuilder<'a, ChaCha20Rng>>,
    kari_builders: Vec<KeyAgreeRecipientInfoBuilder>,
    pwri_builders: Vec<PasswordRecipientInfoBuilder>,
    ori_builders: Vec<OtherRecipientInfoBuilder>,
    is_auth_enveloped: bool,
}

impl<'a> EnvelopedDataBuilder<'a> {
    pub fn new(cae_type: CeaType, is_auth_enveloped: bool) -> Result<Self> {
        if !is_auth_enveloped && !ALLOWED_CAE_TYPES_ENVELOPED.contains(&cae_type) {
            return Err(QuantCryptError::UnsupportedContentEncryptionAlgorithm);
        }

        if is_auth_enveloped && !ALLOWED_CAE_TYPES_AUTH_ENVELOPED.contains(&cae_type) {
            return Err(QuantCryptError::UnsupportedContentEncryptionAlgorithm);
        }

        Ok(Self {
            originator_info: None,
            plaintext: Vec::new(),
            cae_type,
            unprotected_attributes: None,
            auth_attributes: None,
            kemri_builders: Vec::new(),
            kek_builders: Vec::new(),
            ktri_builders: Vec::new(),
            kari_builders: Vec::new(),
            pwri_builders: Vec::new(),
            ori_builders: Vec::new(),
            is_auth_enveloped,
        })
    }

    pub fn unprotected_attribute(&mut self, attribute: &Attribute) -> Result<&mut Self> {
        if let Some(attributes) = &mut self.unprotected_attributes {
            attributes
                .insert(attribute.clone())
                .map_err(|_| QuantCryptError::InvalidAttribute)?;
            Ok(self)
        } else {
            self.unprotected_attributes = Some(Attributes::new());
            let attributes = self.unprotected_attributes.as_mut().unwrap();
            attributes
                .insert(attribute.clone())
                .map_err(|_| QuantCryptError::InvalidAttribute)?;
            Ok(self)
        }
    }

    pub fn auth_attribute(&mut self, attribute: &Attribute) -> Result<&mut Self> {
        if !self.is_auth_enveloped {
            return Err(QuantCryptError::UnsupportedOperation);
        }

        if let Some(attributes) = &mut self.auth_attributes {
            attributes
                .insert(attribute.clone())
                .map_err(|_| QuantCryptError::InvalidAttribute)?;
            Ok(self)
        } else {
            self.auth_attributes = Some(Attributes::new());
            let attributes = self.auth_attributes.as_mut().unwrap();
            attributes
                .insert(attribute.clone())
                .map_err(|_| QuantCryptError::InvalidAttribute)?;
            Ok(self)
        }
    }

    pub fn content(&mut self, content: &[u8]) -> Result<&mut Self> {
        self.plaintext = content.to_vec();
        Ok(self)
    }

    pub fn kem_recipient(
        &mut self,
        cert: &Certificate,
        kdf: &KdfType,
        wrap_type: &WrapType,
        ukm: Option<UserKeyingMaterial>,
    ) -> Result<&mut Self> {
        if !cert.is_key_encipherment_enabled() {
            return Err(QuantCryptError::InvalidCertificate);
        }

        let kdf_oid = kdf.get_oid();
        let wrap_oid = wrap_type.get_oid();

        let kem_manager = kem_manager::KemManager::new_from_oid(&cert.get_public_key_oid())?;
        let kemri_builder = KemRecipientInfoBuilder::new(cert, kem_manager, kdf_oid, wrap_oid, ukm);
        self.kemri_builders.push(kemri_builder);
        Ok(self)
    }

    pub fn kek_recipient(&mut self, builder: KekRecipientInfoBuilder) -> Result<&mut Self> {
        self.kek_builders.push(builder);
        Ok(self)
    }

    pub fn ktri_recipient(
        &mut self,
        builder: KeyTransRecipientInfoBuilder<'a, ChaCha20Rng>,
    ) -> Result<&mut Self> {
        self.ktri_builders.push(builder);
        Ok(self)
    }

    pub fn kari_recipient(&mut self, builder: KeyAgreeRecipientInfoBuilder) -> Result<&mut Self> {
        self.kari_builders.push(builder);
        Ok(self)
    }

    pub fn pwri_recipient(&mut self, builder: PasswordRecipientInfoBuilder) -> Result<&mut Self> {
        self.pwri_builders.push(builder);
        Ok(self)
    }

    pub fn ori_recipient(&mut self, builder: OtherRecipientInfoBuilder) -> Result<&mut Self> {
        self.ori_builders.push(builder);
        Ok(self)
    }

    pub fn originator_info(&mut self, originator_info: OriginatorInfo) -> Result<&mut Self> {
        self.originator_info = Some(originator_info);
        Ok(self)
    }

    fn build_enveloped(self) -> Result<Vec<u8>> {
        let cea = match self.cae_type {
            CeaType::Aes128CbcPad => ContentEncryptionAlgorithm::Aes128Cbc,
            CeaType::Aes192CbcPad => ContentEncryptionAlgorithm::Aes192Cbc,
            CeaType::Aes256CbcPad => ContentEncryptionAlgorithm::Aes256Cbc,
            _ => return Err(QuantCryptError::UnsupportedOperation),
        };

        let mut builder = cms::builder::EnvelopedDataBuilder::new(
            self.originator_info.clone(),
            &self.plaintext,
            cea,
            self.unprotected_attributes.clone(),
        )
        .map_err(|_| QuantCryptError::Unknown)?;

        for kemri_builder in self.kemri_builders {
            let kemri = kemri_builder;
            builder
                .add_recipient_info(kemri)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for kek_builder in self.kek_builders {
            builder
                .add_recipient_info(kek_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for ktri_builder in self.ktri_builders {
            builder
                .add_recipient_info(ktri_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for kari_builder in self.kari_builders {
            builder
                .add_recipient_info(kari_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for pwri_builder in self.pwri_builders {
            builder
                .add_recipient_info(pwri_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for ori_builder in self.ori_builders {
            builder
                .add_recipient_info(ori_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        let mut rng = ChaCha20Rng::from_entropy();

        let enveloped_data = builder
            .build_with_rng(&mut rng)
            .map_err(|_| QuantCryptError::Unknown)?;

        enveloped_data
            .to_der()
            .map_err(|_| QuantCryptError::Unknown)
    }

    pub fn build_auth_enveloped(self) -> Result<Vec<u8>> {
        let cea = match self.cae_type {
            CeaType::Aes128Gcm => ContentEncryptionAlgorithmAead::Aes128Gcm,
            CeaType::Aes192Gcm => ContentEncryptionAlgorithmAead::Aes192Gcm,
            CeaType::Aes256Gcm => ContentEncryptionAlgorithmAead::Aes256Gcm,
            _ => return Err(QuantCryptError::UnsupportedOperation),
        };

        // TODO: If there is any auth attributes, we need to check if the auth attributes
        // contain the content type attribute and message digest attribute. If not, we need to add them.'
        // RFC5652 § 11.1 , § 11.2

        let mut builder = AuthEnvelopedDataBuilder::new(
            None,
            self.originator_info.clone(),
            &self.plaintext,
            cea,
            self.auth_attributes.clone(),
            self.unprotected_attributes.clone(),
        )?;

        for kemri_builder in self.kemri_builders {
            let kemri = kemri_builder;
            builder
                .add_recipient_info(kemri)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for kek_builder in self.kek_builders {
            builder
                .add_recipient_info(kek_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for ktri_builder in self.ktri_builders {
            builder
                .add_recipient_info(ktri_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for kari_builder in self.kari_builders {
            builder
                .add_recipient_info(kari_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for pwri_builder in self.pwri_builders {
            builder
                .add_recipient_info(pwri_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        for ori_builder in self.ori_builders {
            builder
                .add_recipient_info(ori_builder)
                .map_err(|_| QuantCryptError::Unknown)?;
        }

        let enveloped_data = builder.build()?;

        enveloped_data
            .to_der()
            .map_err(|_| QuantCryptError::Unknown)
    }

    pub fn build(self) -> Result<Vec<u8>> {
        let is_auth_enveloped = self.is_auth_enveloped;

        if self.plaintext.is_empty() {
            return Err(QuantCryptError::InvalidContent);
        }

        let data = if !self.is_auth_enveloped {
            self.build_enveloped()?
        } else {
            self.build_auth_enveloped()?
        };

        let content_type_oid = if is_auth_enveloped {
            ID_CT_AUTH_ENVELOPED_DATA
        } else {
            ID_ENVELOPED_DATA
        };

        let cms_content_info = ContentInfo {
            content_type: content_type_oid,
            content: der::Any::from_der(&data).map_err(|_| QuantCryptError::Unknown)?,
        };

        let ci_der = cms_content_info
            .to_der()
            .map_err(|_| QuantCryptError::Unknown)?;

        Ok(ci_der)
    }
}

#[cfg(test)]
mod tests {
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::dsa_trait::Dsa;
    use crate::dsa::common::dsa_type::DsaType;
    use crate::dsa::dsa_manager::DsaManager;
    use crate::kem::common::config::oids::Oid as _;
    use crate::kem::common::kem_type::KemType;
    use crate::{CertValidity, CertificateBuilder, PrivateKey, PublicKey};
    use x509_cert::builder::Profile;

    use crate::{kdf::common::kdf_type::KdfType, wrap::api::WrapType};

    use super::*;

    #[test]
    fn test_enveloped_data_kemri() {
        let plaintext = b"Hello, World!".to_vec();
        let cae_type = CeaType::Aes256CbcPad;
        let mut builder = EnvelopedDataBuilder::new(cae_type, false)
            .expect("Failed to create EnvelopedDataBuilder");

        let cert_ta_1 = Certificate::from_der(include_bytes!("../../test/data/cms_cw/ta.der"))
            .expect("Failed to create Certificate");

        let kdf = KdfType::HkdfWithSha256;
        let wrap = WrapType::Aes256;
        let ukm = None;

        builder.content(&plaintext).unwrap();

        let result = builder.kem_recipient(&cert_ta_1, &kdf, &wrap, ukm.clone());
        assert!(result.is_err());
        assert!(matches!(result, Err(QuantCryptError::InvalidCertificate)));

        let cert_ee_1: Certificate = Certificate::from_der(include_bytes!(
            "../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_ee.der"
        ))
        .expect("Failed to create Certificate");

        let sk_bytes = include_bytes!(
            "../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der"
        );
        let sk_ee_1 = PrivateKey::from_der(sk_bytes).expect("Failed to create PrivateKey");

        builder
            .kem_recipient(&cert_ee_1, &kdf, &wrap, ukm.clone())
            .unwrap();

        // Add a new recipient (of a completely different type)
        let (ta_pk_2, ta_sk_2) = DsaManager::new(DsaType::MlDsa44Rsa2048PssSha256)
            .unwrap()
            .key_gen()
            .unwrap();
        let ta_pk_2 =
            PublicKey::new(&DsaType::MlDsa44Rsa2048PssSha256.get_oid(), &ta_pk_2).unwrap();
        let ta_sk_2 = PrivateKey::new(
            &DsaType::MlDsa44Rsa2048PssSha256.get_oid(),
            &ta_sk_2,
            Some(ta_pk_2.clone()),
        )
        .unwrap();
        let ta_cert_2 = CertificateBuilder::new(
            Profile::Root,
            None,
            CertValidity::new(None, "2025-01-01T00:00:00Z").unwrap(),
            "CN=test.com".to_string(),
            ta_pk_2,
            &ta_sk_2,
        )
        .unwrap()
        .build()
        .unwrap();

        let (ee_pk2, ee_sk2) = kem_manager::KemManager::new(KemType::MlKem768BrainpoolP256r1)
            .unwrap()
            .key_gen()
            .unwrap();

        let ee_pk2 = PublicKey::new(&KemType::MlKem768BrainpoolP256r1.get_oid(), &ee_pk2).unwrap();
        let ee_sk2 = PrivateKey::new(
            &KemType::MlKem768BrainpoolP256r1.get_oid(),
            &ee_sk2.clone(),
            Some(ee_pk2.clone()),
        )
        .unwrap();
        //let spki = SubjectPublicKeyInfo::from_key(ee_pk2).unwrap();
        let validity = CertValidity::new(None, "2025-01-01T00:00:00Z").unwrap(); // Not before is now
        let serial_no = None; // This will generate a random serial number
        let signer = ta_sk_2;
        let subject = "CN=sub.test.com".to_string();

        let ee_cert = CertificateBuilder::new(
            Profile::Leaf {
                issuer: ta_cert_2.get_subject(),
                enable_key_agreement: false,
                enable_key_encipherment: true,
            },
            serial_no,
            validity,
            subject,
            ee_pk2,
            &signer,
        )
        .unwrap()
        .build()
        .unwrap();

        builder.kem_recipient(&ee_cert, &kdf, &wrap, ukm).unwrap();

        let result = builder.build().expect("Failed to build enveloped data");

        // Test if we can decrypt the enveloped data
        let pt = crate::cms::cms_util::CmsUtil::decrypt_kemri(&result, &sk_ee_1, &cert_ee_1)
            .expect("Failed to decrypt enveloped data");

        assert_eq!(pt, plaintext);

        // Test if we can decrypt the enveloped data with the second recipient
        let pt = crate::cms::cms_util::CmsUtil::decrypt_kemri(&result, &ee_sk2, &ee_cert)
            .expect("Failed to decrypt enveloped data");

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_auth_enveloped_data_kemri() {
        let plaintext = b"Hello, World!".to_vec();
        let cae_type = CeaType::Aes256Gcm;
        let mut builder = EnvelopedDataBuilder::new(cae_type, true)
            .expect("Failed to create EnvelopedDataBuilder");

        let cert_ta_1 = Certificate::from_der(include_bytes!("../../test/data/cms_cw/ta.der"))
            .expect("Failed to create Certificate");

        let kdf = KdfType::HkdfWithSha256;
        let wrap = WrapType::Aes256;
        let ukm = None;

        builder.content(&plaintext).unwrap();

        let result = builder.kem_recipient(&cert_ta_1, &kdf, &wrap, ukm.clone());
        assert!(result.is_err());
        assert!(matches!(result, Err(QuantCryptError::InvalidCertificate)));

        let cert_ee_1: Certificate = Certificate::from_der(include_bytes!(
            "../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_ee.der"
        ))
        .expect("Failed to create Certificate");

        let sk_bytes = include_bytes!(
            "../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der"
        );
        let sk_ee_1 = PrivateKey::from_der(sk_bytes).expect("Failed to create PrivateKey");

        builder
            .kem_recipient(&cert_ee_1, &kdf, &wrap, ukm.clone())
            .unwrap();

        // Add a new recipient (of a completely different type)
        let (ta_pk_2, ta_sk_2) = DsaManager::new(DsaType::MlDsa44Rsa2048PssSha256)
            .unwrap()
            .key_gen()
            .unwrap();
        let ta_pk_2 =
            PublicKey::new(&DsaType::MlDsa44Rsa2048PssSha256.get_oid(), &ta_pk_2).unwrap();
        let ta_sk_2 = PrivateKey::new(
            &DsaType::MlDsa44Rsa2048PssSha256.get_oid(),
            &ta_sk_2,
            Some(ta_pk_2.clone()),
        )
        .unwrap();
        let ta_cert_2 = CertificateBuilder::new(
            Profile::Root,
            None,
            CertValidity::new(None, "2025-01-01T00:00:00Z").unwrap(),
            "CN=test.com".to_string(),
            ta_pk_2,
            &ta_sk_2,
        )
        .unwrap()
        .build()
        .unwrap();

        let (ee_pk2, ee_sk2) = kem_manager::KemManager::new(KemType::MlKem768BrainpoolP256r1)
            .unwrap()
            .key_gen()
            .unwrap();

        let ee_pk2 = PublicKey::new(&KemType::MlKem768BrainpoolP256r1.get_oid(), &ee_pk2).unwrap();
        let ee_sk2 = PrivateKey::new(
            &KemType::MlKem768BrainpoolP256r1.get_oid(),
            &ee_sk2.clone(),
            Some(ee_pk2.clone()),
        )
        .unwrap();
        //let spki = SubjectPublicKeyInfo::from_key(ee_pk2).unwrap();
        let validity = CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(); // Not before is now
        let serial_no = None; // This will generate a random serial number
        let signer = ta_sk_2;
        let subject = "CN=sub.test.com".to_string();

        let ee_cert = CertificateBuilder::new(
            Profile::Leaf {
                issuer: ta_cert_2.get_subject(),
                enable_key_agreement: false,
                enable_key_encipherment: true,
            },
            serial_no,
            validity,
            subject,
            ee_pk2,
            &signer,
        )
        .unwrap()
        .build()
        .unwrap();

        builder.kem_recipient(&ee_cert, &kdf, &wrap, ukm).unwrap();

        let result = builder.build().expect("Failed to build enveloped data");

        // Test if we can decrypt the enveloped data
        let pt = crate::cms::cms_util::CmsUtil::decrypt_kemri(&result, &sk_ee_1, &cert_ee_1)
            .expect("Failed to decrypt enveloped data");

        assert_eq!(pt, plaintext);

        // Test if we can decrypt the enveloped data with the second recipient
        let pt = crate::cms::cms_util::CmsUtil::decrypt_kemri(&result, &ee_sk2, &ee_cert)
            .expect("Failed to decrypt enveloped data");

        assert_eq!(pt, plaintext);
    }
}
