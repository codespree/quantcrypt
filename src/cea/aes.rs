use crate::cea::asn1::aes_parameters::AesParameters;
use crate::cea::common::cea_info::CeaInfo;
use crate::cea::common::cea_trait::Cea;
use crate::cea::common::cea_type::CeaType;
use crate::cea::common::config::oids::Oid;
use crate::QuantCryptError;
use cms::enveloped_data::EncryptedContentInfo;
use const_oid::db::rfc5911::ID_DATA;
use der::asn1::{ObjectIdentifier, OctetString};
use der::Decode;
use der::Encode;
use pkcs8::spki::AlgorithmIdentifierOwned;

use openssl::symm::{decrypt, decrypt_aead, encrypt, encrypt_aead, Cipher};

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Clone)]
pub struct Aes {
    cea_type: CeaType,
}

impl Aes {
    fn get_cipher(&self) -> Cipher {
        match self.cea_type {
            CeaType::Aes128Gcm => Cipher::aes_128_gcm(),
            CeaType::Aes192Gcm => Cipher::aes_192_gcm(),
            CeaType::Aes256Gcm => Cipher::aes_256_gcm(),
            CeaType::Aes128CbcPad => Cipher::aes_128_cbc(),
            CeaType::Aes192CbcPad => Cipher::aes_192_cbc(),
            CeaType::Aes256CbcPad => Cipher::aes_256_cbc(),
        }
    }

    fn get_nonce(&self, cipher: &Cipher, nonce: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce_len = cipher.iv_len().unwrap_or(0);
        let nonce = if let Some(nonce) = nonce {
            if nonce.len() != nonce_len {
                return Err(QuantCryptError::Unknown);
            }
            nonce.to_vec()
        } else {
            let mut nonce = vec![0u8; nonce_len];
            openssl::rand::rand_bytes(&mut nonce).map_err(|_| QuantCryptError::Unknown)?;
            nonce
        };
        Ok(nonce)
    }

    fn to_content_info(&self, ct: &[u8], nonce: &[u8], cid: Option<&str>) -> Result<Vec<u8>> {
        let oid: ObjectIdentifier = self
            .cea_type
            .get_oid()
            .parse()
            .map_err(|_| QuantCryptError::Unknown)?;

        let parameters = match self.cea_type {
            CeaType::Aes128Gcm | CeaType::Aes192Gcm | CeaType::Aes256Gcm => {
                AesParameters::new(nonce, 16)
                    .map_err(|_| QuantCryptError::Unknown)?
                    .to_der()
                    .map_err(|_| QuantCryptError::Unknown)?
            }
            CeaType::Aes128CbcPad | CeaType::Aes192CbcPad | CeaType::Aes256CbcPad => {
                OctetString::new(nonce.to_vec())
                    .map_err(|_| QuantCryptError::Unknown)?
                    .to_der()
                    .map_err(|_| QuantCryptError::Unknown)?
            }
        };

        let parameters = der::Any::from_der(&parameters).map_err(|_| QuantCryptError::Unknown)?;
        let enc_algorithm = AlgorithmIdentifierOwned {
            oid,
            parameters: Some(parameters),
        };
        let cid = if let Some(cid) = cid {
            cid.parse().map_err(|_| QuantCryptError::InvalidOid)?
        } else {
            ID_DATA
        };

        let ct_oct_str = OctetString::new(ct.to_vec()).map_err(|_| QuantCryptError::Unknown)?;
        let enc = EncryptedContentInfo {
            content_type: cid,
            content_enc_alg: enc_algorithm,
            encrypted_content: Some(ct_oct_str),
        }
        .to_der()
        .map_err(|_| QuantCryptError::Unknown)?;
        Ok(enc)
    }

    fn from_content_info(tag: &[u8], ct: &[u8]) -> Result<(CeaType, Vec<u8>, Vec<u8>)> {
        let eci =
            EncryptedContentInfo::from_der(ct).map_err(|_| QuantCryptError::InvalidCiphertext)?;
        let alg = eci.content_enc_alg.oid.to_string();
        let alg: CeaType = CeaType::from_oid(&alg).ok_or(QuantCryptError::InvalidCiphertext)?;
        let nonce = match alg {
            CeaType::Aes128Gcm | CeaType::Aes192Gcm | CeaType::Aes256Gcm => {
                // Get the AES parameters
                let params = eci
                    .content_enc_alg
                    .parameters
                    .ok_or(QuantCryptError::InvalidCiphertext)?;
                let params = params
                    .to_der()
                    .map_err(|_| QuantCryptError::InvalidCiphertext)?;
                let params = AesParameters::from_der(&params)
                    .map_err(|_| QuantCryptError::InvalidCiphertext)?;
                let nonce = params.get_nonce();
                let icv_len = params.get_icv_len();
                if icv_len != tag.len() as i8 {
                    return Err(QuantCryptError::InvalidCiphertext);
                }
                nonce.to_vec()
            }
            CeaType::Aes128CbcPad | CeaType::Aes192CbcPad | CeaType::Aes256CbcPad => {
                let params = eci
                    .content_enc_alg
                    .parameters
                    .ok_or(QuantCryptError::InvalidCiphertext)?;
                let params = params
                    .to_der()
                    .map_err(|_| QuantCryptError::InvalidCiphertext)?;
                let params = OctetString::from_der(&params)
                    .map_err(|_| QuantCryptError::InvalidCiphertext)?;
                let nonce = params.as_bytes();
                if nonce != tag {
                    return Err(QuantCryptError::InvalidCiphertext);
                }
                nonce.to_vec()
            }
        };
        let ct = eci
            .encrypted_content
            .ok_or(QuantCryptError::InvalidCiphertext)?;

        Ok((alg, nonce, ct.as_bytes().to_vec()))
    }
}

impl Cea for Aes {
    fn new(cea_type: CeaType) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Aes { cea_type })
    }

    fn get_cea_info(&self) -> CeaInfo {
        CeaInfo::new(self.cea_type.clone())
    }

    fn encrypt(
        &self,
        key: &[u8],
        nonce: Option<&[u8]>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        content_type_oid: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = self.get_cipher();
        let nonce = self.get_nonce(&cipher, nonce)?;

        let mut tag = [0u8; 16];
        let aad = aad.unwrap_or(&[]);

        let (ct, tag) = match self.cea_type {
            CeaType::Aes128Gcm | CeaType::Aes192Gcm | CeaType::Aes256Gcm => (
                encrypt_aead(cipher, key, Some(&nonce), aad, plaintext, &mut tag)
                    .map_err(|_| QuantCryptError::Unknown)?,
                tag.to_vec(),
            ),
            CeaType::Aes128CbcPad | CeaType::Aes192CbcPad | CeaType::Aes256CbcPad => (
                encrypt(cipher, key, Some(&nonce), plaintext)
                    .map_err(|_| QuantCryptError::Unknown)?,
                nonce.clone(),
            ),
        };
        Ok((
            tag.clone(),
            self.to_content_info(&ct, &nonce, content_type_oid)?,
        ))
    }

    fn decrypt(key: &[u8], tag: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let (cea_type, nonce, ct) = Aes::from_content_info(tag, ciphertext)?;
        let cipher = match cea_type {
            CeaType::Aes128Gcm => Cipher::aes_128_gcm(),
            CeaType::Aes192Gcm => Cipher::aes_192_gcm(),
            CeaType::Aes256Gcm => Cipher::aes_256_gcm(),
            CeaType::Aes128CbcPad => Cipher::aes_128_cbc(),
            CeaType::Aes192CbcPad => Cipher::aes_192_cbc(),
            CeaType::Aes256CbcPad => Cipher::aes_256_cbc(),
        };

        let aad = aad.unwrap_or(&[]);

        let result = match cea_type {
            CeaType::Aes128Gcm | CeaType::Aes192Gcm | CeaType::Aes256Gcm => {
                decrypt_aead(cipher, key, Some(&nonce), aad, &ct, tag)
            }
            CeaType::Aes128CbcPad | CeaType::Aes192CbcPad | CeaType::Aes256CbcPad => {
                decrypt(cipher, key, Some(&nonce), &ct)
            }
        }
        .map_err(|_| QuantCryptError::InvalidCiphertext)?;
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<Vec<u8>> {
        let cipher = self.get_cipher();
        let key_len = cipher.key_len();
        let mut key = vec![0u8; key_len];
        openssl::rand::rand_bytes(&mut key).map_err(|_| QuantCryptError::Unknown)?;
        Ok(key)
    }

    fn nonce_gen(&mut self) -> Result<Vec<u8>> {
        let cipher = self.get_cipher();
        let nonce = self.get_nonce(&cipher, None)?;
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cea::common::macros::test_cea;

    #[test]
    fn test_aes128gcm() {
        let mut cea = Aes::new(CeaType::Aes128Gcm).unwrap();
        test_cea!(cea);
    }

    #[test]
    fn test_aes256gcm() {
        let mut cea = Aes::new(CeaType::Aes256Gcm).unwrap();
        test_cea!(cea);
    }

    #[test]
    fn test_aes192gcm() {
        let mut cea = Aes::new(CeaType::Aes192Gcm).unwrap();
        test_cea!(cea);
    }
}
