//https://datatracker.ietf.org/doc/html/rfc3394#section-2.2.1
use super::common::wrap_info::WrapInfo;
use crate::wrap::common::wrap_trait::Wrap;
use crate::{wrap::common::wrap_type::WrapType, QuantCryptError};
type Result<T> = std::result::Result<T, QuantCryptError>;
use openssl::aes::{unwrap_key, wrap_key};
#[derive(Clone)]
pub struct Aes {
    wrap_type: WrapType,
}

impl Wrap for Aes {
    fn new(wrap_type: WrapType) -> Result<Aes> {
        match wrap_type {
            WrapType::Aes128 => Ok(Aes { wrap_type }),
            WrapType::Aes256 => Ok(Aes { wrap_type }),
        }
    }

    fn wrap(&self, wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>> {
        let key_size = match self.wrap_type {
            WrapType::Aes128 => {
                if wrapping_key.len() != 16 || key_to_wrap.len() != 16 {
                    return Err(QuantCryptError::KeyWrapFailed);
                }
                16
            }
            WrapType::Aes256 => {
                if wrapping_key.len() != 32 || key_to_wrap.len() != 32 {
                    return Err(QuantCryptError::KeyWrapFailed);
                }
                32
            }
        };

        let wrapping_key = openssl::aes::AesKey::new_encrypt(wrapping_key)
            .map_err(|_| QuantCryptError::KeyWrapFailed)?;
        let mut out_buf = vec![0u8; key_size + 8];
        wrap_key(&wrapping_key, None, &mut out_buf, key_to_wrap)
            .map_err(|_| QuantCryptError::KeyWrapFailed)?;
        //encrypt_wrap!(Aes128, wrapping_key, key_to_wrap)
        Ok(out_buf)
    }

    fn unwrap(&self, wrapping_key: &[u8], key_to_unwrap: &[u8]) -> Result<Vec<u8>> {
        let key_size = match self.wrap_type {
            WrapType::Aes128 => {
                if wrapping_key.len() != 16 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                if key_to_unwrap.len() != 16 + 8 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                16
            }
            WrapType::Aes256 => {
                if wrapping_key.len() != 32 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                if key_to_unwrap.len() != 32 + 8 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                32
            }
        };
        let key = openssl::aes::AesKey::new_decrypt(wrapping_key)
            .map_err(|_| QuantCryptError::KeyUnwrapFailed)?;
        let mut out_buf = vec![0u8; key_size];
        unwrap_key(&key, None, &mut out_buf, key_to_unwrap)
            .map_err(|_| QuantCryptError::KeyUnwrapFailed)?;

        Ok(out_buf)
    }

    fn get_wrap_info(&self) -> WrapInfo {
        WrapInfo::new(self.wrap_type.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap::common::wrap_type::WrapType;

    #[test]
    fn test_aes_128_wrap_unwrap() {
        let aes = Aes::new(WrapType::Aes128).unwrap();
        let wrapping_key = vec![0u8; 16];
        let key_to_wrap = vec![0u8; 16];
        let wrapped_key = aes.wrap(&wrapping_key, &key_to_wrap).unwrap();
        assert!(wrapped_key.len() == 24);
        let unwrapped_key = aes.unwrap(&wrapping_key, &wrapped_key).unwrap();
        assert_eq!(key_to_wrap, unwrapped_key);
    }

    #[test]
    fn test_aes_128_wrap_unwrap_failure() {
        let aes = Aes::new(WrapType::Aes128).unwrap();
        let wrapping_key = vec![0u8; 16];
        let key_to_wrap = vec![0u8; 32];
        let wrapped_key = aes.wrap(&wrapping_key, &key_to_wrap);
        assert!(wrapped_key.is_err());
        assert!(matches!(
            wrapped_key.unwrap_err(),
            QuantCryptError::KeyWrapFailed
        ));

        let wrapping_key = vec![0u8; 32];
        let key_to_wrap = vec![0u8; 16];
        let wrapped_key = aes.wrap(&wrapping_key, &key_to_wrap);
        assert!(wrapped_key.is_err());
        assert!(matches!(
            wrapped_key.unwrap_err(),
            QuantCryptError::KeyWrapFailed
        ));
    }

    #[test]
    fn test_aes_256_wrap_unwrap() {
        let aes = Aes::new(WrapType::Aes256).unwrap();
        let wrapping_key = vec![0u8; 32];
        let key_to_wrap = vec![0u8; 32];
        let wrapped_key = aes.wrap(&wrapping_key, &key_to_wrap).unwrap();
        assert!(wrapped_key.len() == 40);
        let unwrapped_key = aes.unwrap(&wrapping_key, &wrapped_key).unwrap();
        assert_eq!(key_to_wrap, unwrapped_key);
    }
}
