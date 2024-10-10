use der::asn1::OctetString;
use der_derive::Sequence;

use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Sequence)]
pub struct AesParameters {
    /// AES nonce
    aes_nonce: OctetString,

    /// AES ICV length
    aes_icv_len: i8,
}

impl AesParameters {
    pub fn new(aes_nonce: &[u8], aes_icv_len: i8) -> Result<Self> {
        let aes_nonce =
            OctetString::new(aes_nonce.to_vec()).map_err(|_| QuantCryptError::InvalidAesNonce)?;

        Ok(AesParameters {
            aes_nonce,
            aes_icv_len,
        })
    }

    pub fn get_nonce(&self) -> &[u8] {
        self.aes_nonce.as_bytes()
    }

    pub fn get_icv_len(&self) -> i8 {
        self.aes_icv_len
    }
}
