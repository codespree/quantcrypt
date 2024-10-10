use crate::cea::common::cea_type::CeaType;
use cms::{
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{EnvelopedData, OriginatorInfo, RecipientInfos},
};
use der::{Decode, Encode};
use x509_cert::attr::Attributes;

use crate::{Certificate, PrivateKey, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

use crate::cms::cms_util::CmsUtil;
use const_oid::db::rfc5911::ID_ENVELOPED_DATA;

use crate::cms::enveloped_data_builder::EnvelopedDataBuilder;

/// The content encryption algorithm used to encrypt the content
pub enum ContentEncryptionAlgorithm {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

/// Main interaction point for the EnvelopedData content
///
/// This struct is used to create, read and manipulate EnvelopedData content
///
/// # Example
/// ```
/// use quantcrypt::EnvelopedDataContent;
/// use quantcrypt::ContentEncryptionAlgorithm;
/// use quantcrypt::Certificate;
/// use quantcrypt::PrivateKey;
/// use quantcrypt::KdfType;
/// use quantcrypt::WrapType;
/// use quantcrypt::UserKeyingMaterial;
/// use quantcrypt::ObjectIdentifier;
/// use quantcrypt::Attribute;
/// use quantcrypt::Tag;
/// use quantcrypt::AttributeValue;
/// use quantcrypt::SetOfVec;
///
/// let recipient_cert = Certificate::from_file(
///     "test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_ee.der",
/// )
/// .unwrap();
///
/// let private_key = PrivateKey::from_file(
///     "test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der",
/// )
/// .unwrap();
///
/// let ukm = UserKeyingMaterial::new("test".as_bytes()).unwrap();
/// let data = b"abc";

/// let attribute_oid = ObjectIdentifier::new("1.3.6.1.4.1.22554.5.6").unwrap();
/// let mut attribute_vals: SetOfVec<AttributeValue> = SetOfVec::<AttributeValue>::new();
///
/// let attr_val = AttributeValue::new(Tag::OctetString, data.to_vec()).unwrap();
/// attribute_vals.insert(attr_val).unwrap();
///
/// let attribute = Attribute {
///     oid: attribute_oid,
///     values: attribute_vals,
/// };
///
/// let mut builder =
///     EnvelopedDataContent::get_builder(ContentEncryptionAlgorithm::Aes128Cbc).unwrap();
///
/// builder
///     .kem_recipient(
///         &recipient_cert,
///         &KdfType::HkdfWithSha256,
///         &WrapType::Aes256,
///         Some(ukm),
///     )
///     .unwrap()
///     .content(data)
///     .unwrap()
///     .unprotected_attribute(&attribute)
///     .unwrap();
///
/// let content = builder.build().unwrap();
/// // Now use this content to create a new EnvelopedDataContent
/// let edc = EnvelopedDataContent::from_bytes_for_kem_recipient(
///     &content,
///     &recipient_cert,
///     &private_key,
/// )
/// .unwrap();
/// assert_eq!(edc.get_content(), data);
/// ```

pub struct EnvelopedDataContent {
    version: CmsVersion,
    originator_info: Option<OriginatorInfo>,
    recip_infos: RecipientInfos,
    content: Vec<u8>,
    unprotected_attrs: Option<Attributes>,
}

impl EnvelopedDataContent {
    pub fn from_file_for_kem_recipient(
        file: &str,
        recipient_cert: &Certificate,
        recipient_private_key: &PrivateKey,
    ) -> Result<EnvelopedDataContent> {
        let data = std::fs::read(file).map_err(|_| QuantCryptError::FileReadError)?;
        EnvelopedDataContent::from_bytes_for_kem_recipient(
            &data,
            recipient_cert,
            recipient_private_key,
        )
    }

    pub fn from_bytes_for_kem_recipient(
        data: &[u8],
        recipient_cert: &Certificate,
        recipient_private_key: &PrivateKey,
    ) -> Result<EnvelopedDataContent> {
        // First try to read it as a der encoded ContentInfo
        let ci = if let Ok(content_info) = ContentInfo::from_der(data) {
            content_info
        } else {
            // If that fails, try to read it as a pem encoded ContentInfo
            let pem = pem::parse(data).map_err(|_| QuantCryptError::InvalidContent)?;
            ContentInfo::from_der(pem.contents()).map_err(|_| QuantCryptError::InvalidContent)?
        };

        // Check if the cotent type is EnvelopedData
        if ci.content_type != ID_ENVELOPED_DATA {
            return Err(QuantCryptError::InvalidContent);
        }

        let enveloped_data = ci
            .content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let ed = EnvelopedData::from_der(&enveloped_data)
            .map_err(|_| QuantCryptError::InvalidContent)?;

        // try to decrypt the content
        let pt = CmsUtil::decrypt_kemri(data, recipient_private_key, recipient_cert)?;

        Ok(EnvelopedDataContent {
            version: ed.version,
            originator_info: ed.originator_info,
            recip_infos: ed.recip_infos,
            content: pt,
            unprotected_attrs: ed.unprotected_attrs,
        })
    }

    pub fn get_version(&self) -> CmsVersion {
        self.version
    }

    pub fn get_originator_info(&self) -> Option<OriginatorInfo> {
        self.originator_info.clone()
    }

    pub fn get_content(&self) -> Vec<u8> {
        self.content.clone()
    }

    pub fn get_unprotected_attrs(&self) -> Option<Attributes> {
        self.unprotected_attrs.clone()
    }

    pub fn get_recipient_infos(&self) -> RecipientInfos {
        self.recip_infos.clone()
    }

    pub fn get_builder(
        content_encryption_alg: ContentEncryptionAlgorithm,
    ) -> Result<EnvelopedDataBuilder<'static>> {
        let cea = match content_encryption_alg {
            ContentEncryptionAlgorithm::Aes128Cbc => CeaType::Aes128CbcPad,
            ContentEncryptionAlgorithm::Aes192Cbc => CeaType::Aes192CbcPad,
            ContentEncryptionAlgorithm::Aes256Cbc => CeaType::Aes256CbcPad,
        };
        EnvelopedDataBuilder::new(cea, false)
    }
}

#[cfg(test)]
mod tests {
    use der::{asn1::SetOfVec, Tag, Tagged};
    use spki::ObjectIdentifier;
    use x509_cert::attr::{Attribute, AttributeValue};

    use super::*;
    use crate::{KdfType, UserKeyingMaterial, WrapType};

    #[test]
    fn test_enveloped_data_content() {
        let recipient_cert = Certificate::from_file(
            "test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_ee.der",
        )
        .unwrap();

        let private_key = PrivateKey::from_file(
            "test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der",
        )
        .unwrap();

        let ukm = UserKeyingMaterial::new("test".as_bytes()).unwrap();
        let data = b"abc";

        let attribute_oid = ObjectIdentifier::new("1.3.6.1.4.1.22554.5.6").unwrap();
        let mut attribute_vals: SetOfVec<AttributeValue> = SetOfVec::<AttributeValue>::new();

        let attr_val = AttributeValue::new(Tag::OctetString, data.to_vec()).unwrap();
        attribute_vals.insert(attr_val).unwrap();

        let attribute = Attribute {
            oid: attribute_oid,
            values: attribute_vals,
        };

        let mut builder =
            EnvelopedDataContent::get_builder(ContentEncryptionAlgorithm::Aes128Cbc).unwrap();

        builder
            .kem_recipient(
                &recipient_cert,
                &KdfType::HkdfWithSha256,
                &WrapType::Aes256,
                Some(ukm),
            )
            .unwrap()
            .content(data)
            .unwrap()
            .unprotected_attribute(&attribute)
            .unwrap();

        let content = builder.build().unwrap();

        // Now use this content to create a new EnvelopedDataContent
        let edc = EnvelopedDataContent::from_bytes_for_kem_recipient(
            &content,
            &recipient_cert,
            &private_key,
        )
        .unwrap();

        assert_eq!(edc.get_content(), data);
        assert_eq!(edc.get_recipient_infos().0.len(), 1);
        assert_eq!(edc.get_unprotected_attrs().unwrap().len(), 1);

        // Check the attribute
        let attrs = edc.get_unprotected_attrs().unwrap();
        let attr = attrs.get(0).unwrap();
        assert_eq!(attr.oid.to_string(), "1.3.6.1.4.1.22554.5.6");
        assert_eq!(attr.values.len(), 1);
        let val: AttributeValue = attr.values.get(0).unwrap().clone();
        assert_eq!(val.tag(), Tag::OctetString);
        assert_eq!(val.value(), data);

        // Check the version
        assert_eq!(edc.get_version(), CmsVersion::V3);

        // Check the originator info
        assert_eq!(edc.get_originator_info(), None);

        // Check the recipient infos length
        assert_eq!(edc.get_recipient_infos().0.len(), 1);
    }
}
