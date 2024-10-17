use crate::cea::common::cea_type::CeaType;
use cms::{
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{OriginatorInfo, RecipientInfos},
};
use der::{Decode, Encode};
use x509_cert::attr::Attributes;

use crate::{certificates::Certificate, keys::PrivateKey, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

use crate::cms::cms_util::CmsUtil;
use const_oid::db::rfc5911::ID_CT_AUTH_ENVELOPED_DATA;

use crate::cms::asn1::auth_enveloped_data_builder::ContentEncryptionAlgorithmAead;
use crate::cms::enveloped_data_builder::EnvelopedDataBuilder;

use super::auth_env_data::AuthEnvelopedData;

/// Main interaction point for the AuthEnvelopedData content
///
/// This struct is used to create, read and manipulate AuthEnvelopedData content
///
/// # Example
/// ```
/// use quantcrypt::content::AuthEnvelopedDataContent;
/// use quantcrypt::content::ContentEncryptionAlgorithmAead;
/// use quantcrypt::certificates::Certificate;
/// use quantcrypt::keys::PrivateKey;
/// use quantcrypt::kdfs::KdfType;
/// use quantcrypt::wraps::WrapType;
/// use quantcrypt::content::UserKeyingMaterial;
/// use quantcrypt::content::ObjectIdentifier;
/// use quantcrypt::content::Attribute;
/// use quantcrypt::content::Tag;
/// use quantcrypt::content::AttributeValue;
/// use quantcrypt::content::SetOfVec;
///
// Based on whether IPD feature is enabled or not, use the appropriate test data
/// let rc_filename = "test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_ee.der";
///
/// let recipient_cert = Certificate::from_file(
///     rc_filename,
/// ).unwrap();
///
/// let sk_filename = "test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_priv.der";
///
/// let private_key = PrivateKey::from_file(
///     sk_filename
/// ).unwrap();
///
/// let ukm = UserKeyingMaterial::new("test".as_bytes()).unwrap();
/// let data = b"abc";
///
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
///     AuthEnvelopedDataContent::get_builder(ContentEncryptionAlgorithmAead::Aes256Gcm).unwrap();
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
///     .auth_attribute(&attribute)
///     .unwrap();
///     
///
/// let content = builder.build().unwrap();
/// // Now use this content to create a new EnvelopedDataContent
/// let edc = AuthEnvelopedDataContent::from_bytes_for_kem_recipient(
///     &content,
///     &recipient_cert,
///     &private_key,
/// )
/// .unwrap();
/// assert_eq!(edc.get_content(), data);
/// ```

pub struct AuthEnvelopedDataContent {
    /// The CmsVersion
    version: CmsVersion,
    /// The OriginatorInfo if present
    originator_info: Option<OriginatorInfo>,
    /// The RecipientInfos
    recip_infos: RecipientInfos,
    /// The content
    content: Vec<u8>,
    /// The unprotected attributes
    unprotected_attrs: Option<Attributes>,
    /// The authenticated attributes
    auth_attrs: Option<Attributes>,
}

impl AuthEnvelopedDataContent {
    /// Load a AuthEnvelopedDataContent from a file. The content is wrapped in a ContentInfo
    /// object. The content is decrypted using the provided recipient certificate and private key.
    ///
    /// # Arguments
    ///
    /// * `file` - The file to read the content from
    /// * `recipient_cert` - The recipient certificate
    /// * `recipient_private_key` - The recipient private key
    ///
    /// # Returns
    ///
    /// The AuthEnvelopedDataContent object
    pub fn from_file_for_kem_recipient(
        file: &str,
        recipient_cert: &Certificate,
        recipient_private_key: &PrivateKey,
    ) -> Result<AuthEnvelopedDataContent> {
        let data = std::fs::read(file).map_err(|_| QuantCryptError::FileReadError)?;
        AuthEnvelopedDataContent::from_bytes_for_kem_recipient(
            &data,
            recipient_cert,
            recipient_private_key,
        )
    }

    /// Load a AuthEnvelopedDataContent from a byte array. The content is wrapped in a ContentInfo
    /// object. The content is decrypted using the provided recipient certificate and private key.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte array to read the content from
    /// * `recipient_cert` - The recipient certificate
    /// * `recipient_private_key` - The recipient private key
    ///
    /// # Returns
    ///
    /// The AuthEnvelopedDataContent object
    pub fn from_bytes_for_kem_recipient(
        data: &[u8],
        recipient_cert: &Certificate,
        recipient_private_key: &PrivateKey,
    ) -> Result<AuthEnvelopedDataContent> {
        // First try to read it as a der encoded ContentInfo
        let ci = if let Ok(content_info) = ContentInfo::from_der(data) {
            content_info
        } else {
            // If that fails, try to read it as a pem encoded ContentInfo
            let pem = pem::parse(data).map_err(|_| QuantCryptError::InvalidContent)?;
            ContentInfo::from_der(pem.contents()).map_err(|_| QuantCryptError::InvalidContent)?
        };

        // Check if the cotent type is EnvelopedData
        if ci.content_type != ID_CT_AUTH_ENVELOPED_DATA {
            return Err(QuantCryptError::InvalidContent);
        }

        let enveloped_data = ci
            .content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let ed = AuthEnvelopedData::from_der(&enveloped_data)
            .map_err(|_| QuantCryptError::InvalidContent)?;

        // try to decrypt the content
        let pt = CmsUtil::decrypt_kemri(data, recipient_private_key, recipient_cert)?;

        Ok(AuthEnvelopedDataContent {
            version: ed.version,
            originator_info: ed.originator_info,
            recip_infos: ed.recip_infos,
            content: pt,
            unprotected_attrs: ed.unauth_attrs,
            auth_attrs: ed.auth_attrs,
        })
    }

    /// Get the CmsVersion
    pub fn get_version(&self) -> CmsVersion {
        self.version
    }

    /// Get the OriginatorInfo
    pub fn get_originator_info(&self) -> Option<OriginatorInfo> {
        self.originator_info.clone()
    }

    /// Get the content
    pub fn get_content(&self) -> Vec<u8> {
        self.content.clone()
    }

    /// Get the unprotected attributes
    pub fn get_unprotected_attrs(&self) -> Option<Attributes> {
        self.unprotected_attrs.clone()
    }

    /// Get the authenticated attributes
    pub fn get_auth_attrs(&self) -> Option<Attributes> {
        self.auth_attrs.clone()
    }

    /// Get the RecipientInfos
    pub fn get_recipient_infos(&self) -> RecipientInfos {
        self.recip_infos.clone()
    }

    /// Get a builder for the AuthEnvelopedDataContent. This is used to create new AuthEnvelopedDataContent objects
    ///
    /// # Arguments
    ///
    /// * `content_encryption_alg` - The content encryption algorithm
    ///
    /// # Returns
    ///
    /// The AuthEnvelopedDataContent builder
    pub fn get_builder(
        content_encryption_alg: ContentEncryptionAlgorithmAead,
    ) -> Result<EnvelopedDataBuilder<'static>> {
        let cea = match content_encryption_alg {
            ContentEncryptionAlgorithmAead::Aes128Gcm => CeaType::Aes128Gcm,
            ContentEncryptionAlgorithmAead::Aes192Gcm => CeaType::Aes192Gcm,
            ContentEncryptionAlgorithmAead::Aes256Gcm => CeaType::Aes256Gcm,
        };
        EnvelopedDataBuilder::new(cea, true)
    }
}

#[cfg(test)]
mod tests {
    use der::{asn1::SetOfVec, Tag, Tagged};
    use spki::ObjectIdentifier;
    use x509_cert::attr::{Attribute, AttributeValue};

    use super::*;
    use crate::{content::UserKeyingMaterial, content::WrapType, kdf::common::kdf_type::KdfType};

    #[test]
    fn test_auth_enveloped_data_content() {
        let recipient_cert =
            Certificate::from_file("test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_ee.der").unwrap();

        let private_key =
            PrivateKey::from_file("test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_priv.der")
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
            AuthEnvelopedDataContent::get_builder(ContentEncryptionAlgorithmAead::Aes256Gcm)
                .unwrap();

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
            .unwrap()
            .auth_attribute(&attribute)
            .unwrap();

        let content = builder.build().unwrap();

        // Now use this content to create a new AuthEnvelopedDataContent
        let edc = AuthEnvelopedDataContent::from_bytes_for_kem_recipient(
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

        // Check the auth attribute
        let attrs = edc.get_auth_attrs().unwrap();
        let attr = attrs.get(0).unwrap();
        assert_eq!(attr.oid.to_string(), "1.3.6.1.4.1.22554.5.6");
        assert_eq!(attr.values.len(), 1);
        let val: AttributeValue = attr.values.get(0).unwrap().clone();
        assert_eq!(val.tag(), Tag::OctetString);
        assert_eq!(val.value(), data);

        // Check the version
        assert_eq!(edc.get_version(), CmsVersion::V0);

        // Check the originator info
        assert_eq!(edc.get_originator_info(), None);

        // Check the recipient infos length
        assert_eq!(edc.get_recipient_infos().0.len(), 1);
    }
}
