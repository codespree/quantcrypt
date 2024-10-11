// https://datatracker.ietf.org/doc/rfc9629/

use crate::kdf::common::kdf_trait::Kdf;
use crate::{kdf::common::kdf_type::KdfType, QuantCryptError};

use super::common::kdf_info::KdfInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Clone)]
pub struct Hkdf {
    kdf_type: KdfType,
}

impl Kdf for Hkdf {
    fn new(kdf_type: KdfType) -> Result<Hkdf> {
        match kdf_type {
            KdfType::HkdfWithSha256 | KdfType::HkdfWithSha512 | KdfType::HkdfWithSha384 => Ok(Hkdf { kdf_type }),
            _ => Err(QuantCryptError::NotImplemented),
        }
    }

    fn derive(
        &self,
        ikm: &[u8],
        info: &[u8],
        length: usize,
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.kdf_type {
            KdfType::HkdfWithSha256 => {
                let prk = hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm);
                let mut okm: Vec<u8> = vec![0; length];
                prk.expand(info, &mut okm)
                    .map_err(|_| QuantCryptError::InvalidHkdfLength)?;
                Ok(okm)
            }
            KdfType::HkdfWithSha512 => {
                let prk = hkdf::Hkdf::<sha2::Sha512>::new(salt, ikm);
                let mut okm: Vec<u8> = vec![0; length];
                prk.expand(info, &mut okm)
                    .map_err(|_| QuantCryptError::InvalidHkdfLength)?;
                Ok(okm)
            }
            KdfType::HkdfWithSha384 => {
                let prk = hkdf::Hkdf::<sha2::Sha384>::new(salt, ikm);
                let mut okm: Vec<u8> = vec![0; length];
                prk.expand(info, &mut okm)
                    .map_err(|_| QuantCryptError::InvalidHkdfLength)?;
                Ok(okm)
            }
            _ => Err(QuantCryptError::NotImplemented),
        }
    }

    fn get_kdf_info(&self) -> super::common::kdf_info::KdfInfo {
        KdfInfo::new(self.kdf_type.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::common::kdf_type::KdfType;

    #[test]
    fn test_hkdf_256() {
        let hkdf = Hkdf::new(KdfType::HkdfWithSha256).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"01234567890123456789";
        let chunk_len = 32; // As this is SHA256
        let mut max_len = 255 * chunk_len;
        let length = 0;
        let okm = hkdf.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);
        let okm = hkdf.derive(ikm, info, max_len, None).unwrap();
        assert_eq!(okm.len(), max_len);
        max_len += 1;
        let okm = hkdf.derive(ikm, info, max_len, None);
        assert!(okm.is_err());
        assert_eq!(okm.unwrap_err(), QuantCryptError::InvalidHkdfLength);
    }

    #[test]
    fn test_hkdf_512() {
        let hkdf = Hkdf::new(KdfType::HkdfWithSha512).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"01234567890123456789";
        let chunk_len = 64; // As this is SHA256
        let mut max_len = 255 * chunk_len;
        let length = 0;
        let okm = hkdf.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);
        let okm = hkdf.derive(ikm, info, max_len, None).unwrap();
        assert_eq!(okm.len(), max_len);
        max_len += 1;
        let okm = hkdf.derive(ikm, info, max_len, None);
        assert!(okm.is_err());
        assert_eq!(okm.unwrap_err(), QuantCryptError::InvalidHkdfLength);
    }
}
