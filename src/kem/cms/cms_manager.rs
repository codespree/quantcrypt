//https://datatracker.ietf.org/doc/html/rfc5652
use crate::cea::common::cea_trait::Cea;
use crate::Certificate;
use crate::{
    kdf::common::kdf_trait::Kdf, kem::cms::asn1::kemri::KemRecipientInfo,
    wrap::common::wrap_trait::Wrap, KdfManager, PrivateKey, QuantCryptError, WrapManager,
};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, OtherRecipientInfo, RecipientInfo};
use const_oid::db::rfc5911::{ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA};
use der::{asn1::OctetString, Decode, Encode};

use crate::cea::cea_manager::CeaManager;
use crate::kem::cms::asn1::kemri::CmsOriForKemOtherInfo;

use crate::kem::cms::asn1::auth_env_data::AuthEnvelopedData;

type Result<T> = std::result::Result<T, QuantCryptError>;

pub struct CmsManager {}

impl CmsManager {
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
        let kdf_input = CmsOriForKemOtherInfo {
            wrap: kemri.wrap.clone(),
            kek_length: kemri.kek_length,
            ukm: kemri.ukm,
        };
        let der_kdf_input = kdf_input
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let kdf = KdfManager::new_from_oid(&kemri.kdf.oid.to_string())?;
        let length = kemri.kek_length as usize;
        let kek = kdf.derive(&ss, &der_kdf_input, length, None)?;
        let wrapped_cek = kemri.encrypted_key.as_bytes();
        let wrap = WrapManager::new_from_oid(&kemri.wrap.oid.to_string())?;
        let key = wrap.unwrap(&kek, wrapped_cek)?;
        Ok(key)
    }

    fn decrypt_auth_enveloped(
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
                    let key = Self::get_cek(ori, private_key, cert)?;
                    let result = CeaManager::decrypt(&key, mac, &ct, Some(&aad))?;
                    return Ok(result);
                }
                _ => {
                    // TODO: Handle normal recipient info types
                    // https://github.com/sfackler/rust-openssl/blob/master/openssl/src/cms.rs
                    continue;
                }
            };
        }
        Err(QuantCryptError::InvalidEnvelopedData)
    }

    fn decrypt_enveloped(
        enveloped_data_der: &[u8],
        private_key: &PrivateKey,
        cert: &Certificate,
    ) -> Result<Vec<u8>> {
        let enveloped_data = EnvelopedData::from_der(enveloped_data_der)
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let ct = enveloped_data
            .encrypted_content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        let params = match enveloped_data.encrypted_content.content_enc_alg.parameters {
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

        for ri in enveloped_data.recip_infos.0.iter() {
            match ri {
                RecipientInfo::Ori(ori) => {
                    let key = Self::get_cek(ori, private_key, cert)?;
                    let result = CeaManager::decrypt(&key, iv, &ct, None)?;
                    return Ok(result);
                }
                // TODO: Handle normal recipient info types
                // https://github.com/sfackler/rust-openssl/blob/master/openssl/src/cms.rs
                _ => continue,
            }
        }

        Err(QuantCryptError::InvalidEnvelopedData)
    }

    pub fn decrypt(data: &[u8], private_key: &PrivateKey, cert: &Certificate) -> Result<Vec<u8>> {
        let content_info: ContentInfo =
            ContentInfo::from_der(data).map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let oid = content_info.content_type;
        let enveloped_data = content_info
            .content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        if oid == ID_ENVELOPED_DATA {
            Self::decrypt_enveloped(&enveloped_data, private_key, cert)
        } else if oid == ID_CT_AUTH_ENVELOPED_DATA {
            Self::decrypt_auth_enveloped(&enveloped_data, private_key, cert)
        } else {
            Err(QuantCryptError::InvalidEnvelopedData)
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::Certificate;

    use super::*;

    #[test]
    fn test_enveloped_data() {
        let ta_bytes = include_bytes!("../../../test/data/cms_cw/ta.der");
        let ta = Certificate::from_der(ta_bytes).unwrap();
        let ee_bytes = include_bytes!(
            "../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_ee.der"
        );
        let ee = Certificate::from_der(ee_bytes).unwrap();
        // ee should be signed by ta, this wont verify because of context parameter
        let result = ta.verify_child(&ee).unwrap();
        assert_eq!(result, false);

        let enveloped = include_bytes!("../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-alg-hkdf-with-sha256_ukm.der");

        let sk = include_bytes!(
            "../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der"
        );
        let sk = PrivateKey::from_der(sk).unwrap();

        let result = CmsManager::decrypt(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-alg-hkdf-with-sha256.der");

        let result = CmsManager::decrypt(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-kmac128_ukm.der");

        let result = CmsManager::decrypt(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_auth_id-alg-hkdf-with-sha256_ukm.der");

        let result = CmsManager::decrypt(enveloped, &sk, &ee).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);
    }
}
