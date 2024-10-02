use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeySizeUser;
use aes::Aes128;
use aes::Aes256;

use crate::wrap::common::wrap_trait::Wrap;
use crate::{wrap::common::wrap_type::WrapType, QuantCryptError};
use aes_kw::Kek;

use super::common::wrap_info::WrapInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// Macro for encrypting data using Aes128Wrap, Aes192Wrap or Aes256Wrap
macro_rules! encrypt_wrap {
    ($cek:expr, $alg:ty, $key:ident) => {{
        let kek_buf = GenericArray::from_slice($key);
        let kek = Kek::<$alg>::from(*kek_buf);
        let mut wrapped_key = vec![0u8; <$alg>::key_size() + 8];
        kek.wrap($cek, &mut wrapped_key)
            .map_err(|_| QuantCryptError::KeyWrapFailed)?;
        Ok(wrapped_key.to_vec())
    }};
}

/// Macro for decrypting data using Aes128Wrap, Aes192Wrap or Aes256Wrap
macro_rules! decrypt_wrap {
    ($cek:expr, $alg:ty, $key:ident) => {{
        let kek_buf = GenericArray::from_slice($key);
        let kek = Kek::<$alg>::from(*kek_buf);
        let mut unwrapped_key = vec![0u8; <$alg>::key_size()];
        kek.unwrap($cek, &mut unwrapped_key)
            .map_err(|_| QuantCryptError::KeyUnwrapFailed)?;
        Ok(unwrapped_key.to_vec())
    }};
}

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
        match self.wrap_type {
            WrapType::Aes128 => {
                if wrapping_key.len() != 16 || key_to_wrap.len() != 16 {
                    return Err(QuantCryptError::KeyWrapFailed);
                }

                encrypt_wrap!(wrapping_key, Aes128, key_to_wrap)
            }
            WrapType::Aes256 => {
                if wrapping_key.len() != 32 || key_to_wrap.len() != 32 {
                    return Err(QuantCryptError::KeyWrapFailed);
                }
                encrypt_wrap!(wrapping_key, Aes256, key_to_wrap)
            }
        }
    }

    fn unwrap(&self, wrapping_key: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>> {
        match self.wrap_type {
            WrapType::Aes128 => {
                if wrapping_key.len() != 16 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                decrypt_wrap!(wrapped_key, Aes128, wrapping_key)
            }
            WrapType::Aes256 => {
                if wrapping_key.len() != 32 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                decrypt_wrap!(wrapped_key, Aes256, wrapping_key)
            }
        }
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
        let unwrapped_key = aes.unwrap(&wrapping_key, &wrapped_key).unwrap();
        assert_eq!(key_to_wrap, unwrapped_key);
    }
}
