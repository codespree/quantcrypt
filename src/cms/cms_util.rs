//https://datatracker.ietf.org/doc/html/rfc5652

// https://www.ietf.org/archive/id/draft-ietf-lamps-cms-kyber-02.html

// https://datatracker.ietf.org/doc/rfc9629/

use crate::cea::common::cea_trait::Cea;
use crate::Certificate;
use crate::{
    cms::asn1::kemri::KemRecipientInfo, kdf::api::KdfManager, kdf::common::kdf_trait::Kdf,
    wrap::api::WrapManager, wrap::common::wrap_trait::Wrap, PrivateKey, QuantCryptError,
};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, OtherRecipientInfo, RecipientInfo, UserKeyingMaterial};
use const_oid::db::rfc5911::{ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA};
use der::asn1::{OctetStringRef, SetOfVec};
use der::Tag;
use der::{asn1::OctetString, Decode, Encode};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier};
use x509_cert::attr::{Attribute, AttributeValue};

use crate::cea::cea_manager::CeaManager;
use crate::cms::asn1::kemri::CmsOriForKemOtherInfo;

use crate::cms::asn1::auth_env_data::AuthEnvelopedData;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A utility class for CMS operations
pub(crate) struct CmsUtil {}

impl CmsUtil {
    /// Get the key encryption key (KEK) for a shared secret
    ///
    /// # Arguments
    ///
    /// * `ss` - The shared secret
    /// * `wrap_oid` - The OID of the key wrap algorithm
    /// * `kdf_oid` - The OID of the key derivation function
    /// * `kek_length` - The length of the KEK
    /// * `ukm` - The user keying material
    ///
    /// # Returns
    ///
    /// The KEK as bytes
    pub fn get_kek(
        ss: &[u8],
        wrap_oid: &str,
        kdf_oid: &str,
        kek_length: u16,
        ukm: Option<UserKeyingMaterial>,
    ) -> Result<Vec<u8>> {
        let wrap_oid: ObjectIdentifier =
            wrap_oid.parse().map_err(|_| QuantCryptError::InvalidOid)?;
        let wrap = AlgorithmIdentifierOwned {
            oid: wrap_oid,
            parameters: None,
        };

        let kdf_input = CmsOriForKemOtherInfo {
            wrap,
            kek_length,
            ukm,
        };
        let der_kdf_input = kdf_input
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let kdf = KdfManager::new_from_oid(kdf_oid)?;
        let length = kek_length as usize;
        let kek = kdf.derive(ss, &der_kdf_input, length, None)?;
        Ok(kek)
    }

    /// Get the content encryption key (CEK) for a recipient
    ///
    /// # Arguments
    ///
    /// * `ori` - The OtherRecipientInfo. The value of this field should be a KemRecipientInfo as DER bytes
    /// * `private_key` - The private key of the recipient
    /// * `cert` - The certificate of the recipient
    ///
    /// # Returns
    ///
    /// The CEK as bytes
    fn get_cek(
        ori: &OtherRecipientInfo,
        private_key: &PrivateKey,
        cert: &Certificate,
    ) -> Result<Vec<u8>> {
        let ori_value = ori
            .ori_value
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let kemri = KemRecipientInfo::from_der(&ori_value)
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        if !cert.is_identified_by(&kemri.rid) {
            return Err(QuantCryptError::InvalidCertificate);
        }

        let kem_ct = kemri.kem_ct.as_bytes();
        let ss = private_key.decap(kem_ct)?;

        let kek = Self::get_kek(
            &ss,
            &kemri.wrap.oid.to_string(),
            &kemri.kdf.oid.to_string(),
            kemri.kek_length,
            kemri.ukm,
        )?;

        let wrapped_cek = kemri.encrypted_key.as_bytes();
        let wrap = WrapManager::new_from_oid(&kemri.wrap.oid.to_string())?;
        let key = wrap.unwrap(&kek, wrapped_cek)?;
        Ok(key)
    }

    fn decrypt_auth_enveloped_kemri(
        auth_enveloped_data_der: &[u8],
        private_key: &PrivateKey,
        cert: &Certificate,
    ) -> Result<Vec<u8>> {
        let ed = AuthEnvelopedData::from_der(auth_enveloped_data_der)
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let ct = ed
            .auth_encrypted_content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let aad = match &ed.auth_attrs {
            Some(attrs) => attrs
                .to_der()
                .map_err(|_| QuantCryptError::InvalidEnvelopedData)?,
            None => "".as_bytes().to_vec(),
        };

        let mac = ed.mac.as_bytes();

        for ri in ed.recip_infos.0.iter() {
            match ri {
                RecipientInfo::Ori(ori) => {
                    if let Ok(key) = Self::get_cek(ori, private_key, cert) {
                        let result = CeaManager::decrypt(&key, mac, &ct, Some(&aad))?;
                        return Ok(result);
                    } else {
                        continue;
                    }
                }
                _ => {
                    continue;
                }
            };
        }
        Err(QuantCryptError::InvalidEnvelopedData)
    }

    fn decrypt_enveloped_kemri(
        enveloped_data_der: &[u8],
        private_key: &PrivateKey,
        cert: &Certificate,
    ) -> Result<Vec<u8>> {
        let ed = EnvelopedData::from_der(enveloped_data_der)
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let ct = ed
            .encrypted_content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let params = match ed.encrypted_content.content_enc_alg.parameters {
            Some(p) => p,
            None => {
                return Err(QuantCryptError::InvalidEnvelopedData);
            }
        };
        let enc_params = params
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let os_iv = OctetString::from_der(&enc_params)
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let iv: &[u8] = os_iv.as_bytes();

        for ri in ed.recip_infos.0.iter() {
            match ri {
                RecipientInfo::Ori(ori) => {
                    if let Ok(key) = Self::get_cek(ori, private_key, cert) {
                        let result = CeaManager::decrypt(&key, iv, &ct, None)?;
                        return Ok(result);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        Err(QuantCryptError::InvalidEnvelopedData)
    }

    pub fn decrypt_kemri(
        data: &[u8],
        private_key: &PrivateKey,
        cert: &Certificate,
    ) -> Result<Vec<u8>> {
        let content_info: ContentInfo =
            ContentInfo::from_der(data).map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let oid = content_info.content_type;
        let enveloped_data = content_info
            .content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        if oid == ID_ENVELOPED_DATA {
            Self::decrypt_enveloped_kemri(&enveloped_data, private_key, cert)
        } else if oid == ID_CT_AUTH_ENVELOPED_DATA {
            Self::decrypt_auth_enveloped_kemri(&enveloped_data, private_key, cert)
        } else {
            Err(QuantCryptError::InvalidEnvelopedData)
        }
    }

    /// Create a content-type attribute according to
    /// [RFC 5652 § 11.1](https://datatracker.ietf.org/doc/html/rfc5652#section-11.1)
    #[allow(dead_code)]
    pub(crate) fn create_content_type_attribute(
        content_type: ObjectIdentifier,
    ) -> Result<Attribute> {
        let content_type_bytes = content_type.as_bytes();

        let content_type_attribute_value =
            AttributeValue::new(Tag::ObjectIdentifier, content_type_bytes)
                .map_err(|_| QuantCryptError::InvalidAttribute)?;
        let mut values = SetOfVec::new();
        values
            .insert(content_type_attribute_value)
            .map_err(|_| QuantCryptError::InvalidAttribute)?;
        let attribute = Attribute {
            oid: const_oid::db::rfc5911::ID_CONTENT_TYPE,
            values,
        };
        Ok(attribute)
    }

    /// Create a message digest attribute according to
    /// [RFC 5652 § 11.2](https://datatracker.ietf.org/doc/html/rfc5652#section-11.2)
    #[allow(dead_code)]
    pub(crate) fn create_message_digest_attribute(message_digest: &[u8]) -> Result<Attribute> {
        let message_digest_der =
            OctetStringRef::new(message_digest).map_err(|_| QuantCryptError::InvalidAttribute)?;
        use der::Tag::OctetString;
        let message_digest_attribute_value =
            AttributeValue::new(OctetString, message_digest_der.as_bytes())
                .map_err(|_| QuantCryptError::InvalidAttribute)?;
        let mut values = SetOfVec::new();
        values
            .insert(message_digest_attribute_value)
            .map_err(|_| QuantCryptError::InvalidAttribute)?;
        let attribute = Attribute {
            oid: const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
            values,
        };
        Ok(attribute)
    }
}
#[cfg(test)]
mod tests {
    use crate::Certificate;

    use super::*;

    #[test]
    fn test_enveloped_data() {
        let ta_bytes = include_bytes!("../../test/data/cms_cw/ta.der");
        let ta = Certificate::from_der(ta_bytes).unwrap();
        let ee_bytes =
            include_bytes!("../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_ee.der");
        let ee = Certificate::from_der(ee_bytes).unwrap();
        // ee should be signed by ta, this wont verify because of context parameter
        let result = ta.verify_child(&ee).unwrap();
        assert_eq!(result, false);

        let enveloped = include_bytes!("../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-alg-hkdf-with-sha256_ukm.der");

        let sk = include_bytes!(
            "../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der"
        );
        let sk = PrivateKey::from_der(sk).unwrap();

        let result = CmsUtil::decrypt_kemri(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-alg-hkdf-with-sha256.der");

        let result = CmsUtil::decrypt_kemri(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-kmac128_ukm.der");

        let result = CmsUtil::decrypt_kemri(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_auth_id-alg-hkdf-with-sha256_ukm.der");

        let result = CmsUtil::decrypt_kemri(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);
    }
}
