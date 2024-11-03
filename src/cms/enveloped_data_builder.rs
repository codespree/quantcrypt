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

use crate::{
    cea::common::cea_type::CeaType, certificates::Certificate, kem::kem_manager, QuantCryptError,
};

use crate::cms::asn1::kemri_builder::KemRecipientInfoBuilder;

use super::asn1::auth_enveloped_data_builder::{
    AuthEnvelopedDataBuilder, ContentEncryptionAlgorithmAead,
};

type Result<T> = std::result::Result<T, QuantCryptError>;

const ALLOWED_CEA_TYPES_ENVELOPED: [CeaType; 3] = [
    CeaType::Aes128CbcPad,
    CeaType::Aes192CbcPad,
    CeaType::Aes256CbcPad,
];

const ALLOWED_CEA_TYPES_AUTH_ENVELOPED: [CeaType; 3] =
    [CeaType::Aes128Gcm, CeaType::Aes192Gcm, CeaType::Aes256Gcm];

/// A builder for creating an EnvelopedData or AuthEnvelopedData
pub struct EnvelopedDataBuilder<'a> {
    /// The originator info
    originator_info: Option<OriginatorInfo>,
    /// The plaintext content
    plaintext: Vec<u8>,
    /// The content encryption algorithm type
    cea_type: CeaType,
    /// The unprotected attributes
    unprotected_attributes: Option<Attributes>,
    /// The authenticated attributes
    auth_attributes: Option<Attributes>,
    /// The KEM recipient info builders
    kemri_builders: Vec<KemRecipientInfoBuilder>,
    /// The KEK recipient info builders
    kek_builders: Vec<KekRecipientInfoBuilder>,
    /// The KeyTrans recipient info builders
    ktri_builders: Vec<KeyTransRecipientInfoBuilder<'a, ChaCha20Rng>>,
    /// The KeyAgree recipient info builders
    kari_builders: Vec<KeyAgreeRecipientInfoBuilder>,
    /// The Password recipient info builders
    pwri_builders: Vec<PasswordRecipientInfoBuilder>,
    /// The Other recipient info builders (other than Kem Recipient Info, and other types)
    ori_builders: Vec<OtherRecipientInfoBuilder>,
    /// Whether this is an AuthEnvelopedData
    is_auth_enveloped: bool,
}

impl<'a> EnvelopedDataBuilder<'a> {
    /// Create a new EnvelopedDataBuilder
    ///
    /// # Arguments
    ///
    /// * `cea_type` - The type of content encryption algorithm to use
    /// * `is_auth_enveloped` - Whether this is an AuthEnvelopedData
    ///
    /// # Returns
    ///
    /// A new EnvelopedDataBuilder
    pub(crate) fn new(cea_type: CeaType, is_auth_enveloped: bool) -> Result<Self> {
        if !is_auth_enveloped && !ALLOWED_CEA_TYPES_ENVELOPED.contains(&cea_type) {
            return Err(QuantCryptError::UnsupportedContentEncryptionAlgorithm);
        }

        if is_auth_enveloped && !ALLOWED_CEA_TYPES_AUTH_ENVELOPED.contains(&cea_type) {
            return Err(QuantCryptError::UnsupportedContentEncryptionAlgorithm);
        }

        Ok(Self {
            originator_info: None,
            plaintext: Vec::new(),
            cea_type,
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

    /// Add an unprotected attribute
    ///
    /// # Arguments
    ///
    /// * `attribute` - The attribute to add
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
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

    /// Add an authenticated attribute
    ///
    /// # Arguments
    ///
    /// * `attribute` - The attribute to add
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    ///
    /// # Errors
    ///
    /// `QuantCryptError::UnsupportedOperation` if this is not a builder for AuthEnvelopedData
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

    /// Set the content of the EnvelopedData / AuthEnvelopedData
    ///
    /// # Arguments
    ///
    /// * `content` - The content to set
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn content(&mut self, content: &[u8]) -> Result<&mut Self> {
        self.plaintext = content.to_vec();
        Ok(self)
    }

    /// Add a KEM recipient
    ///
    /// # Arguments
    ///
    /// * `cert` - The certificate of the recipient
    /// * `kdf` - The key derivation function to use
    /// * `wrap_type` - The key wrap type to use
    /// * `ukm` - The user keying material to use
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
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

    /// Add a KEK recipient
    ///
    /// # Arguments
    ///
    /// * `builder` - The KEK recipient info builder
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn kek_recipient(&mut self, builder: KekRecipientInfoBuilder) -> Result<&mut Self> {
        self.kek_builders.push(builder);
        Ok(self)
    }

    /// Add a KeyTrans recipient
    ///
    /// # Arguments
    ///
    /// * `builder` - The KeyTrans recipient
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn ktri_recipient(
        &mut self,
        builder: KeyTransRecipientInfoBuilder<'a, ChaCha20Rng>,
    ) -> Result<&mut Self> {
        self.ktri_builders.push(builder);
        Ok(self)
    }

    /// Add a KeyAgree recipient
    ///
    /// # Arguments
    ///
    /// * `builder` - The KeyAgree recipient
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn kari_recipient(&mut self, builder: KeyAgreeRecipientInfoBuilder) -> Result<&mut Self> {
        self.kari_builders.push(builder);
        Ok(self)
    }

    /// Add a Password recipient
    ///
    /// # Arguments
    ///
    /// * `builder` - The Password recipient
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn pwri_recipient(&mut self, builder: PasswordRecipientInfoBuilder) -> Result<&mut Self> {
        self.pwri_builders.push(builder);
        Ok(self)
    }

    /// Add an Other recipient
    ///
    /// # Arguments
    ///
    /// * `builder` - The Other recipient
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn ori_recipient(&mut self, builder: OtherRecipientInfoBuilder) -> Result<&mut Self> {
        self.ori_builders.push(builder);
        Ok(self)
    }

    /// Set the originator info
    ///
    /// # Arguments
    ///
    /// * `originator_info` - The originator info to set
    ///
    /// # Returns
    ///
    /// A mutable reference to the builder
    pub fn originator_info(&mut self, originator_info: OriginatorInfo) -> Result<&mut Self> {
        self.originator_info = Some(originator_info);
        Ok(self)
    }

    /// Build the EnvelopedData
    fn build_enveloped(self) -> Result<Vec<u8>> {
        let cea = match self.cea_type {
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

    /// Build the AuthEnvelopedData
    pub fn build_auth_enveloped(self) -> Result<Vec<u8>> {
        let cea = match self.cea_type {
            CeaType::Aes128Gcm => ContentEncryptionAlgorithmAead::Aes128Gcm,
            CeaType::Aes192Gcm => ContentEncryptionAlgorithmAead::Aes192Gcm,
            CeaType::Aes256Gcm => ContentEncryptionAlgorithmAead::Aes256Gcm,
            _ => return Err(QuantCryptError::UnsupportedOperation),
        };

        // There is no need to add Message Digest or Content Type attributes to the AuthEnvelopedData
        // Content Type only needs to be added if it is not the default value ID_DATA. See the
        // discussion here:
        // https://github.com/codespree/quantcrypt/issues/1

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

    /// Build the EnvelopedData or AuthEnvelopedData and returns the DER bytes
    ///
    /// # Returns
    ///
    /// The DER bytes of the EnvelopedData or AuthEnvelopedData
    pub fn build(self) -> Result<Vec<u8>> {
        let is_auth_enveloped = self.is_auth_enveloped;

        if self.plaintext.is_empty() {
            return Err(QuantCryptError::EmptyContent);
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

    /// Build the EnvelopedData or AuthEnvelopedData and write it to a file
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to write the file to
    pub fn build_to_file(self, file_path: &str) -> Result<()> {
        let data = self.build()?;
        std::fs::write(file_path, data).map_err(|_| QuantCryptError::FileWriteError)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::vec;

    use crate::content::{AuthEnvelopedDataContent, EnvelopedDataContent};
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::prehash_dsa_trait::PrehashDsa;
    use crate::dsa::common::prehash_dsa_type::PrehashDsaType;
    use crate::dsa::dsa_manager::PrehashDsaManager;
    use crate::dsas::{DsaAlgorithm, DsaKeyGenerator};
    use crate::kem::common::config::oids::Oid as _;
    use crate::kem::common::kem_type::KemType;
    use crate::kems::{KemAlgorithm, KemKeyGenerator};
    use crate::{
        certificates::{CertValidity, CertificateBuilder},
        keys::{PrivateKey, PublicKey},
    };
    use x509_cert::builder::Profile;

    use crate::{kdf::common::kdf_type::KdfType, wrap::api::WrapType};

    use super::*;

    #[test]
    fn test_enveloped_data_kemri() {
        let plaintext = b"Hello, World!".to_vec();
        let cea_type = CeaType::Aes256CbcPad;
        let mut builder = EnvelopedDataBuilder::new(cea_type, false)
            .expect("Failed to create EnvelopedDataBuilder");

        let cert_ta_1 = Certificate::from_der(include_bytes!(
            "../../test/data/cms/2.16.840.1.101.3.4.3.17_MlDsa44_ta.der"
        ))
        .expect("Failed to create Certificate");

        let kdf = KdfType::HkdfWithSha256;
        let wrap = WrapType::Aes256;
        let ukm = None;

        builder.content(&plaintext).unwrap();

        let result = builder.kem_recipient(&cert_ta_1, &kdf, &wrap, ukm.clone());
        assert!(result.is_err());
        assert!(matches!(result, Err(QuantCryptError::InvalidCertificate)));

        let cert_ee_1: Certificate = Certificate::from_der(include_bytes!(
            "../../test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_ee.der"
        ))
        .expect("Failed to create Certificate");

        let sk_bytes =
            include_bytes!("../../test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_priv.der");

        let sk_ee_1 = PrivateKey::from_der(sk_bytes).expect("Failed to create PrivateKey");

        builder
            .kem_recipient(&cert_ee_1, &kdf, &wrap, ukm.clone())
            .unwrap();

        // Add a new recipient (of a completely different type)
        let (ta_pk_2, ta_sk_2) = PrehashDsaManager::new(PrehashDsaType::MlDsa44Rsa2048Pss)
            .unwrap()
            .key_gen()
            .unwrap();
        let ta_pk_2 =
            PublicKey::new(&PrehashDsaType::MlDsa44Rsa2048Pss.get_oid(), &ta_pk_2).unwrap();
        let ta_sk_2 =
            PrivateKey::new(&PrehashDsaType::MlDsa44Rsa2048Pss.get_oid(), &ta_sk_2).unwrap();
        let ta_cert_2 = CertificateBuilder::new(
            Profile::Root,
            None,
            CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(),
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
        let ee_sk2 =
            PrivateKey::new(&KemType::MlKem768BrainpoolP256r1.get_oid(), &ee_sk2.clone()).unwrap();
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

    #[test]
    fn test_auth_enveloped_data_kemri() {
        let plaintext = b"Hello, World!".to_vec();
        let cea_type = CeaType::Aes256Gcm;
        let mut builder = EnvelopedDataBuilder::new(cea_type, true)
            .expect("Failed to create EnvelopedDataBuilder");

        let cert_ta_1 = Certificate::from_der(include_bytes!(
            "../../test/data/cms/2.16.840.1.101.3.4.3.17_MlDsa44_ta.der"
        ))
        .expect("Failed to create Certificate");

        let kdf = KdfType::HkdfWithSha256;
        let wrap = WrapType::Aes256;
        let ukm = None;

        builder.content(&plaintext).unwrap();

        let result = builder.kem_recipient(&cert_ta_1, &kdf, &wrap, ukm.clone());
        assert!(result.is_err());
        assert!(matches!(result, Err(QuantCryptError::InvalidCertificate)));

        let cert_ee_1: Certificate = Certificate::from_der(include_bytes!(
            "../../test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_ee.der"
        ))
        .expect("Failed to create Certificate");

        let sk_bytes =
            include_bytes!("../../test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_priv.der");

        let sk_ee_1 = PrivateKey::from_der(sk_bytes).expect("Failed to create PrivateKey");

        builder
            .kem_recipient(&cert_ee_1, &kdf, &wrap, ukm.clone())
            .unwrap();

        // Add a new recipient (of a completely different type)
        let (ta_pk_2, ta_sk_2) = PrehashDsaManager::new(PrehashDsaType::MlDsa44Rsa2048Pss)
            .unwrap()
            .key_gen()
            .unwrap();
        let ta_pk_2 =
            PublicKey::new(&PrehashDsaType::MlDsa44Rsa2048Pss.get_oid(), &ta_pk_2).unwrap();
        let ta_sk_2 =
            PrivateKey::new(&PrehashDsaType::MlDsa44Rsa2048Pss.get_oid(), &ta_sk_2).unwrap();
        let ta_cert_2 = CertificateBuilder::new(
            Profile::Root,
            None,
            CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(),
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
        let ee_sk2 =
            PrivateKey::new(&KemType::MlKem768BrainpoolP256r1.get_oid(), &ee_sk2.clone()).unwrap();
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

    #[test]
    fn gen_cms_artifacts() {
        let ta_types = vec![DsaAlgorithm::MlDsa65, DsaAlgorithm::MlDsa87];

        let kem_types = vec![
            vec![
                KemAlgorithm::MlKem768,
                KemAlgorithm::MlKem768Rsa2048,
                KemAlgorithm::MlKem768Rsa3072,
                KemAlgorithm::MlKem768Rsa4096,
                KemAlgorithm::MlKem768X25519,
                KemAlgorithm::MlKem768P384,
                KemAlgorithm::MlKem768BrainpoolP256r1,
            ],
            vec![
                KemAlgorithm::MlKem1024,
                KemAlgorithm::MlKem1024P384,
                KemAlgorithm::MlKem1024BrainpoolP384r1,
                KemAlgorithm::MlKem1024X448,
            ],
        ];

        let kdf_friendly_name_map = HashMap::from([
            (KdfType::HkdfWithSha256, "id-alg-hkdf-with-sha256"),
            (KdfType::Kmac256, "id-kmac256"),
        ]);

        use crate::content::ContentEncryptionAlgorithm;
        use crate::content::ContentEncryptionAlgorithmAead;

        struct KdfWrapCeaTriple {
            kdf: KdfType,
            wrap: WrapType,
            cea: (ContentEncryptionAlgorithm, ContentEncryptionAlgorithmAead),
        }

        let kdf_wrap_cea_triple_map_data = vec![
            // Pure: https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-kyber/
            (
                KemAlgorithm::MlKem768,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem1024,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
            // Composites: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/05/
            // Section 8.1
            (
                KemAlgorithm::MlKem768Rsa2048,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes128,
                    cea: (
                        ContentEncryptionAlgorithm::Aes128Cbc,
                        ContentEncryptionAlgorithmAead::Aes128Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem768Rsa3072,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes128,
                    cea: (
                        ContentEncryptionAlgorithm::Aes128Cbc,
                        ContentEncryptionAlgorithmAead::Aes128Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem768Rsa4096,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes128,
                    cea: (
                        ContentEncryptionAlgorithm::Aes128Cbc,
                        ContentEncryptionAlgorithmAead::Aes128Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem768X25519,
                KdfWrapCeaTriple {
                    kdf: KdfType::Kmac256,
                    wrap: WrapType::Aes128,
                    cea: (
                        ContentEncryptionAlgorithm::Aes128Cbc,
                        ContentEncryptionAlgorithmAead::Aes128Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem768P384,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem768BrainpoolP256r1,
                KdfWrapCeaTriple {
                    kdf: KdfType::HkdfWithSha256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem1024P384,
                KdfWrapCeaTriple {
                    kdf: KdfType::Kmac256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem1024BrainpoolP384r1,
                KdfWrapCeaTriple {
                    kdf: KdfType::Kmac256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
            (
                KemAlgorithm::MlKem1024X448,
                KdfWrapCeaTriple {
                    kdf: KdfType::Kmac256,
                    wrap: WrapType::Aes256,
                    cea: (
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithmAead::Aes256Gcm,
                    ),
                },
            ),
        ];

        let mut kdf_wrap_cea_triple_map: HashMap<KemAlgorithm, KdfWrapCeaTriple> = HashMap::new();
        for (kem_type, kdf_wrap_cea_triple) in kdf_wrap_cea_triple_map_data {
            kdf_wrap_cea_triple_map.insert(kem_type, kdf_wrap_cea_triple);
        }

        for i in 0..ta_types.len() {
            let ta_type = ta_types[i];
            let ta_oid = ta_type.get_oid();
            let ta_friendly_name = ta_type.to_string();

            let mut ta_key_gen = DsaKeyGenerator::new(ta_type);
            let (ta_pk, ta_sk) = ta_key_gen.generate().unwrap();

            let ta_cert_builder = CertificateBuilder::new(
                Profile::Root,
                None,
                CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(),
                "CN=IETF Hackathon".to_string(),
                ta_pk,
                &ta_sk,
            )
            .unwrap();

            let ta_cert = ta_cert_builder.build().unwrap();
            let ta_cert_path = format!("artifacts/v2_cms/{}_{}_ta.der", ta_oid, ta_friendly_name);
            ta_cert.to_der_file(&ta_cert_path).unwrap();

            let kem_types = &kem_types[i];
            for j in 0..kem_types.len() {
                let kem_type = kem_types[j];
                let kem_oid = kem_type.get_oid();
                let kem_friendly_name = kem_type.to_string();

                let kdf_wrap_cea_triple = kdf_wrap_cea_triple_map.get(&kem_type).unwrap();
                let kdf = kdf_wrap_cea_triple.kdf.clone();
                let wrap = kdf_wrap_cea_triple.wrap.clone();
                let cea_enveloped = kdf_wrap_cea_triple.cea.0.clone();
                let cea_auth_enveloped = kdf_wrap_cea_triple.cea.1.clone();

                let kdf_friendly_name = kdf_friendly_name_map.get(&kdf).unwrap();

                let mut kem_key_gen = KemKeyGenerator::new(kem_type);
                let (ee_pk, ee_sk) = kem_key_gen.generate().unwrap();

                let ee_cert_builder = CertificateBuilder::new(
                    Profile::Leaf {
                        issuer: ta_cert.get_subject(),
                        enable_key_agreement: false,
                        enable_key_encipherment: true,
                    },
                    None,
                    CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(),
                    "CN=IETF Hackathon".to_string(),
                    ee_pk,
                    &ta_sk,
                )
                .unwrap();

                let ee_cert = ee_cert_builder.build().unwrap();
                let ee_cert_path =
                    format!("artifacts/v2_cms/{}_{}_ee.der", kem_oid, kem_friendly_name);
                ee_cert.to_der_file(&ee_cert_path).unwrap();

                assert!(ta_cert.verify_child(&ee_cert).unwrap());

                // Write the private key to a file
                ee_sk
                    .to_der_file(&format!(
                        "artifacts/v2_cms/{}_{}_priv.der",
                        kem_oid, kem_friendly_name
                    ))
                    .unwrap();

                // Build enveloped data
                let path = format!(
                    "artifacts/v2_cms/{}_{}_kemri_{}.der",
                    kem_oid, kem_friendly_name, kdf_friendly_name
                );

                let mut builder = EnvelopedDataContent::get_builder(cea_enveloped.clone()).unwrap();
                builder.kem_recipient(&ee_cert, &kdf, &wrap, None).unwrap();
                let plain_text = include_bytes!("../../artifacts/v2_cms/expected_plaintext.txt");
                builder.content(plain_text).unwrap();

                builder.build_to_file(&path).unwrap();
                println!("Generated: {}", path);

                let enveloped_data =
                    EnvelopedDataContent::from_file_for_kem_recipient(&path, &ee_cert, &ee_sk)
                        .unwrap();
                let pt = enveloped_data.get_content();
                assert_eq!(pt, plain_text);

                let path = format!(
                    "artifacts/v2_cms/{}_{}_kemri_{}_ukm.der",
                    kem_oid, kem_friendly_name, kdf_friendly_name
                );
                let ukm = include_bytes!("../../artifacts/v2_cms/ukm.txt");
                let ukm_os = der::asn1::OctetString::new(ukm.to_vec()).unwrap();
                let mut builder = EnvelopedDataContent::get_builder(cea_enveloped).unwrap();
                builder
                    .kem_recipient(&ee_cert, &kdf, &wrap, Some(ukm_os))
                    .unwrap();
                builder.content(plain_text).unwrap();

                builder.build_to_file(&path).unwrap();
                println!("Generated: {}", path);

                let enveloped_data =
                    EnvelopedDataContent::from_file_for_kem_recipient(&path, &ee_cert, &ee_sk)
                        .unwrap();
                let pt = enveloped_data.get_content();
                assert_eq!(pt, plain_text);

                let path = format!(
                    "artifacts/v2_cms/{}_{}_kemri_{}_auth.der",
                    kem_oid, kem_friendly_name, kdf_friendly_name
                );

                let mut builder =
                    AuthEnvelopedDataContent::get_builder(cea_auth_enveloped).unwrap();
                builder.kem_recipient(&ee_cert, &kdf, &wrap, None).unwrap();
                builder.content(plain_text).unwrap();

                builder.build_to_file(&path).unwrap();
                println!("Generated: {}", path);

                let auth_enveloped_data =
                    AuthEnvelopedDataContent::from_file_for_kem_recipient(&path, &ee_cert, &ee_sk)
                        .unwrap();
                let pt = auth_enveloped_data.get_content();
                assert_eq!(pt, plain_text);
            }
        }
    }

    #[test]
    fn test_cw_cms_artifacts() {
        let security_levels = vec!["512", "768", "1024"];
        let oids = vec!["1", "2", "3"]; // Last digit of OID

        // Materials shared across all test combinations
        let expected_plaintext =
            include_bytes!("../../artifacts/cms_cw/expected_plaintext.txt").to_vec();

        // Function to generate paths for a given base filename
        fn generate_paths(base_filename: &str) -> Vec<String> {
            let base_path = format!("artifacts/cms_cw/{}", base_filename);

            let kemri_path = base_path.clone();
            let kemri_ukm_path = format!("{}_ukm.der", base_path.trim_end_matches(".der"));
            let kemri_auth_path = base_path.replace("kemri", "kemri_auth");
            let kemri_auth_ukm_path =
                format!("{}_ukm.der", kemri_auth_path.trim_end_matches(".der"));

            vec![
                kemri_path,
                kemri_ukm_path,
                kemri_auth_path,
                kemri_auth_ukm_path,
            ]
        }

        // Iterate pairwise over security_levels and oids
        for (security_level, oid) in security_levels.iter().zip(oids.iter()) {
            // Update ee_path and priv_path based on the security level and oid
            let ee_path = format!(
                "artifacts/cms_cw/2.16.840.1.101.3.4.4.{}_ML-KEM-{}_ee.der",
                oid, security_level
            );
            let priv_path = format!(
                "artifacts/cms_cw/2.16.840.1.101.3.4.4.{}_ML-KEM-{}_priv.der",
                oid, security_level
            );

            // Update base_filenames to contain the corresponding security level and oid
            let base_filenames = vec![
                format!(
                    "2.16.840.1.101.3.4.4.{}_ML-KEM-{}_kemri_id-alg-hkdf-with-sha256.der",
                    oid, security_level
                ),
                format!(
                    "2.16.840.1.101.3.4.4.{}_ML-KEM-{}_kemri_id-alg-hkdf-with-sha384.der",
                    oid, security_level
                ),
                format!(
                    "2.16.840.1.101.3.4.4.{}_ML-KEM-{}_kemri_id-alg-hkdf-with-sha512.der",
                    oid, security_level
                ),
                format!(
                    "2.16.840.1.101.3.4.4.{}_ML-KEM-{}_kemri_id-kmac128.der",
                    oid, security_level
                ),
                format!(
                    "2.16.840.1.101.3.4.4.{}_ML-KEM-{}_kemri_id-kmac256.der",
                    oid, security_level
                ),
            ];

            // Generate a list of tuples containing the filename and its corresponding paths
            let tuples_list: Vec<(String, Vec<String>)> = base_filenames
                .iter()
                .map(|filename| (filename.clone(), generate_paths(filename)))
                .collect();

            // Load the certificates and keys
            let ee_cert = Certificate::from_file(&ee_path).unwrap();
            let ee_sk = PrivateKey::from_file(&priv_path).unwrap();

            // Iterate through the list of tuples and process each set of paths
            for (_filename, paths) in tuples_list {
                // Destructure the vector of paths to name each component
                if paths.len() != 4 {
                    panic!("Expected 4 paths, but got {}", paths.len());
                }

                // Manually destructure using indexing
                let kemri_path = &paths[0];
                let kemri_ukm_path = &paths[1];
                let kemri_auth_path = &paths[2];
                let kemri_auth_ukm_path = &paths[3];

                // Enveloped data
                let enveloped_data = EnvelopedDataContent::from_file_for_kem_recipient(
                    &kemri_path,
                    &ee_cert,
                    &ee_sk,
                )
                .unwrap();
                let pt = enveloped_data.get_content();
                assert_eq!(pt, expected_plaintext);

                // With ukm
                let enveloped_data_with_ukm = EnvelopedDataContent::from_file_for_kem_recipient(
                    &kemri_ukm_path,
                    &ee_cert,
                    &ee_sk,
                )
                .unwrap();
                let pt = enveloped_data_with_ukm.get_content();
                assert_eq!(pt, expected_plaintext);

                // Auth
                let auth_enveloped_data = AuthEnvelopedDataContent::from_file_for_kem_recipient(
                    &kemri_auth_path,
                    &ee_cert,
                    &ee_sk,
                )
                .unwrap();
                let pt = auth_enveloped_data.get_content();
                assert_eq!(pt, expected_plaintext);

                // Auth with ukm
                let auth_enveloped_data_with_ukm =
                    AuthEnvelopedDataContent::from_file_for_kem_recipient(
                        &kemri_auth_ukm_path,
                        &ee_cert,
                        &ee_sk,
                    )
                    .unwrap();
                let pt = auth_enveloped_data_with_ukm.get_content();
                assert_eq!(pt, expected_plaintext);
            }
        }
    }
}
