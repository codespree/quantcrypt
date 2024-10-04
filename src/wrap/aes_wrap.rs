//https://datatracker.ietf.org/doc/html/rfc3394#section-2.2.1
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
    ($alg:ty, $kek:expr, $key_to_wrap:ident) => {{
        let kek_buf = GenericArray::from_slice($kek);
        let kek = Kek::<$alg>::from(*kek_buf);
        let mut wrapped_key = vec![0u8; <$alg>::key_size() + 8];
        kek.wrap($key_to_wrap, &mut wrapped_key)
            .map_err(|_| QuantCryptError::KeyWrapFailed)?;
        Ok(wrapped_key.to_vec())
    }};
}

/// Macro for decrypting data using Aes128Wrap, Aes192Wrap or Aes256Wrap
macro_rules! decrypt_wrap {
    ($alg:ty, $kek:ident, $key_to_unwrap:expr) => {{
        let kek_buf = GenericArray::from_slice($kek);
        let kek = Kek::<$alg>::from(*kek_buf);
        let mut unwrapped_key = vec![0u8; <$alg>::key_size()];
        kek.unwrap($key_to_unwrap, &mut unwrapped_key)
            .map_err(|err| {
                println!("Error: {:?}", err);
                QuantCryptError::KeyUnwrapFailed
            })?;
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
                encrypt_wrap!(Aes128, wrapping_key, key_to_wrap)
            }
            WrapType::Aes256 => {
                if wrapping_key.len() != 32 || key_to_wrap.len() != 32 {
                    return Err(QuantCryptError::KeyWrapFailed);
                }
                encrypt_wrap!(Aes256, wrapping_key, key_to_wrap)
            }
        }
    }

    fn unwrap(&self, wrapping_key: &[u8], key_to_unwrap: &[u8]) -> Result<Vec<u8>> {
        match self.wrap_type {
            WrapType::Aes128 => {
                if wrapping_key.len() != 16 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                if key_to_unwrap.len() != 16 + 8 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                decrypt_wrap!(Aes128, wrapping_key, key_to_unwrap)
            }
            WrapType::Aes256 => {
                if wrapping_key.len() != 32 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                if key_to_unwrap.len() != 32 + 8 {
                    return Err(QuantCryptError::KeyUnwrapFailed);
                }
                decrypt_wrap!(Aes256, wrapping_key, key_to_unwrap)
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
