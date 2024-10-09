use crate::cea::common::cea_trait::Cea;
use cms::authenticated_data::MessageAuthenticationCode;
use cms::builder::Error;
use cms::content_info::CmsVersion;
use cms::enveloped_data::{EncryptedContentInfo, RecipientInfo, RecipientInfos};
use cms::{builder::RecipientInfoBuilder, enveloped_data::OriginatorInfo};
use const_oid::db::rfc5911::{ID_AES_128_GCM, ID_AES_192_GCM, ID_AES_256_GCM};
use der::{Decode, Encode};
use spki::ObjectIdentifier;
use x509_cert::attr::Attributes;
use zeroize::Zeroize;

use crate::cea::cea_manager::CeaManager;
use crate::cea::common::cea_type::CeaType;
use crate::QuantCryptError;

use crate::cms::asn1::auth_env_data::AuthEnvelopedData;

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentEncryptionAlgorithmAead {
    /// AES-128 GCM
    Aes128Gcm,
    /// AES-192 GCM
    Aes192Gcm,
    /// AES-256 GCM
    Aes256Gcm,
}

/// Builds CMS `AuthEnvelopedData` according to RFC 5083 § 2.1.
pub struct AuthEnvelopedDataBuilder<'c> {
    content_id: Option<ObjectIdentifier>,
    originator_info: Option<OriginatorInfo>,
    recipient_infos: Vec<Box<dyn RecipientInfoBuilder + 'c>>,
    unencrypted_content: &'c [u8],
    // TODO bk Not good to offer both, `content_encryptor` and `content_encryption_algorithm`.
    // We should
    // (1) either derive `content_encryption_algorithm` from `content_encryptor` (but this is not
    //            yet supported by RustCrypto),
    // (2) or     pass `content_encryption_algorithm` and create an encryptor for it.
    // In the first case, we might need a new trait here, e.g. `DynEncryptionAlgorithmIdentifier` in
    // analogy to `DynSignatureAlgorithmIdentifier`.
    // Going for (2)
    //  content_encryptor: E,
    content_encryption_algorithm: ContentEncryptionAlgorithmAead,
    auth_attributes: Option<Attributes>,
    unauth_attributes: Option<Attributes>,
}

impl ContentEncryptionAlgorithmAead {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentEncryptionAlgorithmAead::Aes128Gcm => ID_AES_128_GCM,
            ContentEncryptionAlgorithmAead::Aes192Gcm => ID_AES_192_GCM,
            ContentEncryptionAlgorithmAead::Aes256Gcm => ID_AES_256_GCM,
        }
    }
}

impl<'c> AuthEnvelopedDataBuilder<'c> {
    /// Create a new builder for `AuthEnvelopedData`
    pub fn new(
        content_id: Option<ObjectIdentifier>,
        originator_info: Option<OriginatorInfo>,
        unencrypted_content: &'c [u8],
        content_encryption_algorithm: ContentEncryptionAlgorithmAead,
        auth_attributes: Option<Attributes>,
        unauth_attributes: Option<Attributes>,
    ) -> Result<AuthEnvelopedDataBuilder<'c>> {
        Ok(AuthEnvelopedDataBuilder {
            content_id,
            originator_info,
            recipient_infos: Vec::new(),
            unencrypted_content,
            content_encryption_algorithm,
            auth_attributes,
            unauth_attributes,
        })
    }

    /// Add recipient info. A builder is used, which generates a `RecipientInfo` according to
    /// RFC 5652 § 6.2, when `AuthEnvelopedData` is built.
    pub fn add_recipient_info(
        &mut self,
        recipient_info_builder: impl RecipientInfoBuilder + 'c,
    ) -> Result<&mut Self> {
        self.recipient_infos.push(Box::new(recipient_info_builder));
        Ok(self)
    }

    /// Generate an `AuthEnvelopedData` object according to RFC 5083 § 2.2 using a provided
    /// random number generator.
    pub fn build(&mut self) -> Result<AuthEnvelopedData> {
        // DER encode authenticated attributes, if any
        // Generate content encryption key
        // Encrypt content and capture authentication tag
        // Build recipient infos
        // Make sure, content encryption key is securely destroyed
        let aad = match &self.auth_attributes {
            Some(attrs) => Some(attrs.to_der().map_err(|_| QuantCryptError::Unknown)?),
            None => None,
        };

        let oid = self.content_encryption_algorithm.oid().to_string();
        let cea_type = if let Some(oid) = CeaType::from_oid(&oid) {
            oid
        } else {
            return Err(QuantCryptError::Unknown);
        };

        // Create an instance of CAE
        let mut cae = CeaManager::new(cea_type)?;
        // Generate a symmetric key
        let mut cek = cae.key_gen()?;
        let nonce = cae.nonce_gen()?;

        // Convert content id to string
        let content_id = self.content_id.map(|oid| oid.to_string());

        let (tag, eci) = cae.encrypt(
            &cek,
            Some(&nonce),
            self.unencrypted_content,
            aad.as_deref(),
            content_id.as_deref(),
        )?;

        type Result<T> = core::result::Result<T, Error>;

        let recipient_infos_vec = self
            .recipient_infos
            .iter_mut()
            .map(|ri| ri.build(&cek))
            .collect::<Result<Vec<RecipientInfo>>>()
            .map_err(|_| QuantCryptError::Unknown)?;

        cek.zeroize();
        let recip_infos =
            RecipientInfos::try_from(recipient_infos_vec).map_err(|_| QuantCryptError::Unknown)?;

        let mac = MessageAuthenticationCode::new(tag).map_err(|_| QuantCryptError::Unknown)?;

        let eci = EncryptedContentInfo::from_der(&eci).map_err(|_| QuantCryptError::Unknown)?;

        Ok(AuthEnvelopedData {
            version: self.calculate_version(),
            originator_info: self.originator_info.clone(),
            recip_infos,
            auth_encrypted_content: eci,
            auth_attrs: self.auth_attributes.clone(),
            mac,
            unauth_attrs: self.unauth_attributes.clone(),
        })
    }

    /// Calculate the `CMSVersion` of the `AuthEnvelopedData` according to RFC 5083 § 2.1, i.e., "MUST be set to 0"
    fn calculate_version(&self) -> CmsVersion {
        CmsVersion::V0
    }
}
