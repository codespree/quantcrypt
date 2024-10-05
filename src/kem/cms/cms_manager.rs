use cms::enveloped_data::{EnvelopedData, RecipientInfo};
use der::{asn1::OctetString, Decode, Encode};

use crate::cea::common::cea_trait::Cea;
use crate::{
    kdf::common::kdf_trait::Kdf, kem::cms::asn1::kemri::KemRecipientInfo,
    wrap::common::wrap_trait::Wrap, KdfManager, PrivateKey, QuantCryptError, WrapManager,
};
use cms::content_info::ContentInfo;
use const_oid::db::rfc5911::{ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA};

use crate::cea::cea_manager::CeaManager;
use crate::kem::cms::asn1::kemri::CmsOriForKemOtherInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;
use crate::kem::cms::cert_store_trait::CertificateStore;

pub struct CmsManager {}

impl CmsManager {
    fn decrypt_enveloped(
        enveloped_data_der: &[u8],
        private_key: &PrivateKey,
        auth: &impl CertificateStore,
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
                    let ori_value = ori
                        .ori_value
                        .to_der()
                        .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
                    let kemri = KemRecipientInfo::from_der(&ori_value)
                        .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

                    let cert = auth.find(kemri.rid.clone());
                    if cert.is_none() {
                        continue;
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
                    let result = CeaManager::decrypt(&key, iv, &ct, None)?;
                    return Ok(result);
                    //RecipientInfo::Ktri(ktri) => process_ktri(ktri, ee_sk)?,
                }
                _ => continue,
            }
        }

        Err(QuantCryptError::InvalidEnvelopedData)
    }

    pub fn decrypt(
        data: &[u8],
        private_key: &PrivateKey,
        auth: &impl CertificateStore,
    ) -> Result<Vec<u8>> {
        let content_info: ContentInfo =
            ContentInfo::from_der(data).map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let oid = content_info.content_type;
        let enveloped_data = content_info
            .content
            .to_der()
            .map_err(|_| QuantCryptError::InvalidEnvelopedData)?;

        if oid == ID_ENVELOPED_DATA {
            Self::decrypt_enveloped(&enveloped_data, private_key, auth)
        } else if oid == ID_CT_AUTH_ENVELOPED_DATA {
            let _ = 0;
            Err(QuantCryptError::InvalidEnvelopedData)
            //return Self::decrypt_auth_enveloped(&enveloped_data, private_key);
        } else {
            Err(QuantCryptError::InvalidEnvelopedData)
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{kem::cms::dummy_cert_store::DummyCertificateStore, Certificate};

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

        let auth = DummyCertificateStore::new();

        let result = CmsManager::decrypt(enveloped, &sk, &auth).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        let enveloped = include_bytes!("../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-alg-hkdf-with-sha256.der");

        let result = CmsManager::decrypt(enveloped, &sk, &auth).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);

        //1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-kmac128_ukm.der
        let enveloped = include_bytes!("../../../test/data/cms_cw/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-kmac128_ukm.der");

        let result = CmsManager::decrypt(enveloped, &sk, &auth).unwrap();
        assert_eq!(result.len(), 3);
        let expected = b"abc";
        assert_eq!(result, expected);
    }
}
