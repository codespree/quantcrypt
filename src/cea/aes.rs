use crate::cea::asn1::aes_parameters::AesParameters;
use crate::cea::common::cea_info::CeaInfo;
use crate::cea::common::cea_trait::Cea;
use crate::cea::common::cea_type::CeaType;
use crate::cea::common::config::oids::Oid;
use crate::QuantCryptError;
use aes::cipher::generic_array::typenum::U12;
use aes::cipher::KeyIvInit;
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::aes::Aes192;
use aes_gcm::{AeadCore, AesGcm, KeyInit};
use cipher::{BlockDecryptMut, BlockEncryptMut};
use cms::enveloped_data::EncryptedContentInfo;
use const_oid::db::rfc5911::ID_DATA;
use der::asn1::{ObjectIdentifier, OctetString};
use der::Decode;
use der::Encode;
use pkcs8::spki::AlgorithmIdentifierOwned;
use rand::SeedableRng;

type Result<T> = std::result::Result<T, QuantCryptError>;

type Aes192Gcm = AesGcm<Aes192, U12>;

type Aes128CbcPadDecryptor = cbc::Decryptor<Aes128>;
type Aes192CbcPadDecryptor = cbc::Decryptor<Aes192>;
type Aes256CbcPadDecryptor = cbc::Decryptor<Aes256>;

type Aes128CbcPadEncryptor = cbc::Encryptor<Aes128>;
type Aes192CbcPadEncryptor = cbc::Encryptor<Aes192>;
type Aes256CbcPadEncryptor = cbc::Encryptor<Aes256>;

use aes_gcm::aes::cipher::generic_array::GenericArray;
pub use aes_gcm::Aes128Gcm;
pub use aes_gcm::Aes256Gcm;

macro_rules! aes_encrypt {
    ($self: expr, $alg: ident, $key: expr, $nonce: expr, $plaintext: expr, $aad: expr, $content_type_oid: expr) => {{
        let cipher = $alg::new($key.into());
        let rng = rand_chacha::ChaCha20Rng::from_entropy();

        let nonce: GenericArray<u8, _> = if let Some(nonce) = $nonce {
            *aes_gcm::Nonce::from_slice(nonce)
        } else {
            let nonce = $alg::generate_nonce(rng);
            nonce
        };

        let ct = if let Some(aad) = $aad {
            let payload = aes_gcm::aead::Payload {
                aad: aad.into(),
                msg: $plaintext.into(),
            };
            let ct = cipher
                .encrypt(&nonce, payload)
                .map_err(|_| QuantCryptError::Unknown)?;
            ct
        } else {
            let ct = cipher
                .encrypt(&nonce, $plaintext)
                .map_err(|_| QuantCryptError::Unknown)?;
            ct
        };

        // Extract the tag from the ciphertext
        let (ct, tag) = ct.split_at(ct.len() - 16);

        let oid: ObjectIdentifier = $self
            .cea_type
            .get_oid()
            .parse()
            .map_err(|_| QuantCryptError::Unknown)?;

        let parameters =
            AesParameters::new(&nonce, tag.len() as i8).map_err(|_| QuantCryptError::Unknown)?;

        let parameters = parameters.to_der().map_err(|_| QuantCryptError::Unknown)?;

        let parameters = der::Any::from_der(&parameters).map_err(|_| QuantCryptError::Unknown)?;

        let enc_algorithm = AlgorithmIdentifierOwned {
            oid,
            parameters: Some(parameters),
        };

        let cid = if let Some(cid) = $content_type_oid {
            cid.parse().map_err(|_| QuantCryptError::InvalidOid)?
        } else {
            ID_DATA
        };

        let ct_oct_str = OctetString::new(ct.to_vec()).map_err(|_| QuantCryptError::Unknown)?;

        let enc = EncryptedContentInfo {
            content_type: cid,
            content_enc_alg: enc_algorithm,
            encrypted_content: Some(ct_oct_str),
        };

        Ok((
            tag.to_vec(),
            enc.to_der().map_err(|_| QuantCryptError::Unknown)?,
        ))
    }};
}

macro_rules! aes_decrypt {
    ($alg: ident, $eci:expr, $key: expr, $tag: expr, $aad: expr) => {{
        let cipher = $alg::new($key.into());
        let params = $eci
            .content_enc_alg
            .parameters
            .ok_or(QuantCryptError::InvalidCipherText)?;
        let params = params
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCipherText)?;
        let params =
            AesParameters::from_der(&params).map_err(|_| QuantCryptError::InvalidCipherText)?;
        let nonce = params.get_nonce();
        let icv_len = params.get_icv_len();
        if icv_len != $tag.len() as i8 {
            return Err(QuantCryptError::InvalidCipherText);
        }
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let ct = $eci
            .encrypted_content
            .ok_or(QuantCryptError::InvalidCipherText)?;
        let ct = ct.as_bytes();

        // Add the tag to the end of the ciphertext
        let mut ct = ct.to_vec();
        ct.extend($tag);

        let ct = ct.as_slice();

        let dec = if let Some(aad) = $aad {
            let payload = aes_gcm::aead::Payload {
                aad: aad.into(),
                msg: ct.into(),
            };
            let dec = cipher
                .decrypt(&nonce, payload)
                .map_err(|_| QuantCryptError::InvalidCiphertext)?;
            dec
        } else {
            let dec = cipher
                .decrypt(&nonce, ct)
                .map_err(|_| QuantCryptError::InvalidCiphertext)?;
            dec
        };
        Ok(dec)
    }};
}

macro_rules! aes_cbc_encrypt {
    ($self: expr, $alg: ident, $key: expr, $nonce: expr, $plaintext: expr, $content_type_oid: expr) => {{
        let rng = rand_chacha::ChaCha20Rng::from_entropy();

        let nonce = if let Some(nonce) = $nonce {
            nonce.to_vec()
        } else {
            let nonce = $alg::generate_iv(rng);
            let nonce = nonce.to_vec();
            nonce
        };

        let cipher = $alg::new_from_slices($key, &nonce).map_err(|_| QuantCryptError::Unknown)?;

        let ct = cipher.encrypt_padded_vec_mut::<cipher::block_padding::Pkcs7>($plaintext);

        let oid: ObjectIdentifier = $self
            .cea_type
            .get_oid()
            .parse()
            .map_err(|_| QuantCryptError::Unknown)?;

        let parameters = OctetString::new(nonce.to_vec()).map_err(|_| QuantCryptError::Unknown)?;

        let parameters = parameters.to_der().map_err(|_| QuantCryptError::Unknown)?;

        let parameters = der::Any::from_der(&parameters).map_err(|_| QuantCryptError::Unknown)?;

        let enc_algorithm = AlgorithmIdentifierOwned {
            oid,
            parameters: Some(parameters),
        };

        let cid = if let Some(cid) = $content_type_oid {
            cid.parse().map_err(|_| QuantCryptError::InvalidOid)?
        } else {
            ID_DATA
        };

        let ct_oct_str = OctetString::new(ct.to_vec()).map_err(|_| QuantCryptError::Unknown)?;

        let enc = EncryptedContentInfo {
            content_type: cid,
            content_enc_alg: enc_algorithm,
            encrypted_content: Some(ct_oct_str),
        };

        Ok((
            nonce.to_vec(),
            enc.to_der().map_err(|_| QuantCryptError::Unknown)?,
        ))
    }};
}

macro_rules! aes_cbc_decrypt {
    ($alg: ident, $eci:expr, $key: expr, $tag: expr) => {{
        let key = GenericArray::from_slice(&$key);
        let cipher = <$alg>::new(key, $tag.into());

        let params = $eci
            .content_enc_alg
            .parameters
            .ok_or(QuantCryptError::InvalidCipherText)?;

        let params = params
            .to_der()
            .map_err(|_| QuantCryptError::InvalidCipherText)?;

        let os_iv =
            OctetString::from_der(&params).map_err(|_| QuantCryptError::InvalidEnvelopedData)?;
        let iv: &[u8] = os_iv.as_bytes();

        if iv != $tag {
            return Err(QuantCryptError::InvalidCipherText);
        }

        let ct = $eci
            .encrypted_content
            .ok_or(QuantCryptError::InvalidCipherText)?;
        let ct = ct.as_bytes();

        cipher
            .decrypt_padded_vec_mut::<cipher::block_padding::Pkcs7>(ct)
            .map_err(|_| QuantCryptError::InvalidCipherText)
    }};
}

#[derive(Clone)]
pub struct Aes {
    cea_type: CeaType,
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
        match self.cea_type {
            CeaType::Aes128Gcm => {
                aes_encrypt!(
                    self,
                    Aes128Gcm,
                    key,
                    nonce,
                    plaintext,
                    aad,
                    content_type_oid
                )
            }
            CeaType::Aes192Gcm => {
                aes_encrypt!(
                    self,
                    Aes192Gcm,
                    key,
                    nonce,
                    plaintext,
                    aad,
                    content_type_oid
                )
            }
            CeaType::Aes256Gcm => {
                aes_encrypt!(
                    self,
                    Aes256Gcm,
                    key,
                    nonce,
                    plaintext,
                    aad,
                    content_type_oid
                )
            }
            CeaType::Aes128CbcPad => {
                aes_cbc_encrypt!(
                    self,
                    Aes128CbcPadEncryptor,
                    key,
                    nonce,
                    plaintext,
                    content_type_oid
                )
            }
            CeaType::Aes192CbcPad => {
                aes_cbc_encrypt!(
                    self,
                    Aes192CbcPadEncryptor,
                    key,
                    nonce,
                    plaintext,
                    content_type_oid
                )
            }
            CeaType::Aes256CbcPad => {
                aes_cbc_encrypt!(
                    self,
                    Aes256CbcPadEncryptor,
                    key,
                    nonce,
                    plaintext,
                    content_type_oid
                )
            }
        }
    }

    fn decrypt(key: &[u8], tag: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let eci = EncryptedContentInfo::from_der(ciphertext)
            .map_err(|_| QuantCryptError::InvalidCipherText)?;
        let alg = eci.content_enc_alg.oid.to_string();
        let alg = CeaType::from_oid(&alg).ok_or(QuantCryptError::InvalidCipherText)?;
        match alg {
            CeaType::Aes128Gcm => aes_decrypt!(Aes128Gcm, eci, key, tag, aad),
            CeaType::Aes192Gcm => aes_decrypt!(Aes192Gcm, eci, key, tag, aad),
            CeaType::Aes256Gcm => aes_decrypt!(Aes256Gcm, eci, key, tag, aad),
            CeaType::Aes128CbcPad => {
                aes_cbc_decrypt!(Aes128CbcPadDecryptor, eci, key, tag)
            }
            CeaType::Aes192CbcPad => {
                aes_cbc_decrypt!(Aes192CbcPadDecryptor, eci, key, tag)
            }
            CeaType::Aes256CbcPad => {
                aes_cbc_decrypt!(Aes256CbcPadDecryptor, eci, key, tag)
            }
        }
    }

    fn key_gen(&mut self) -> Result<Vec<u8>> {
        let rng = rand_chacha::ChaCha20Rng::from_entropy();
        match self.cea_type {
            CeaType::Aes128Gcm => {
                let key = Aes128Gcm::generate_key(rng);
                Ok(key.to_vec())
            }
            CeaType::Aes192Gcm => {
                let key = Aes192Gcm::generate_key(rng);
                Ok(key.to_vec())
            }
            CeaType::Aes256Gcm => {
                let key = Aes256Gcm::generate_key(rng);
                Ok(key.to_vec())
            }
            CeaType::Aes128CbcPad => {
                let key = Aes128::generate_key(rng);
                Ok(key.to_vec())
            }
            CeaType::Aes192CbcPad => {
                let key = Aes192::generate_key(rng);
                Ok(key.to_vec())
            }
            CeaType::Aes256CbcPad => {
                let key = Aes256::generate_key(rng);
                Ok(key.to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cea::common::macros::test_cea;

    #[test]
    fn test_aes128gcm() {
        let mut cae = Aes::new(CeaType::Aes128Gcm).unwrap();
        test_cea!(cae);
    }

    #[test]
    fn test_aes256gcm() {
        let mut cae = Aes::new(CeaType::Aes256Gcm).unwrap();
        test_cea!(cae);
    }

    #[test]
    fn test_aes192gcm() {
        let mut cae = Aes::new(CeaType::Aes192Gcm).unwrap();
        test_cea!(cae);
    }
}
