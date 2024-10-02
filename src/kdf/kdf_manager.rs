use crate::kdf::common::kdf_trait::Kdf;
use crate::kdf::common::kdf_type::KdfType;
use crate::kdf::hkdf::Hkdf;
use crate::kdf::kmac::Kmac;
use crate::QuantCryptError;

use crate::kdf::common::kdf_info::KdfInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

const HKDF_TYPES: [KdfType; 2] = [KdfType::HkdfWithSha256, KdfType::HkdfWithSha512];
const KMAC_TYPES: [KdfType; 2] = [KdfType::Kmac128, KdfType::Kmac256];

// Implement clone
#[derive(Clone)]
/// Enum to representthe different types of KEM managers
pub enum KdfManager {
    /// Hkdf implementation
    Hkdf(Hkdf),
    /// Kmac implementation
    Kmac(Kmac),
}

impl Kdf for KdfManager {
    fn new(kdf_type: KdfType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match kdf_type {
            _ if HKDF_TYPES.contains(&kdf_type) => KdfManager::Hkdf(Hkdf::new(kdf_type)?),
            _ if KMAC_TYPES.contains(&kdf_type) => KdfManager::Kmac(Kmac::new(kdf_type)?),
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn get_kdf_info(&self) -> KdfInfo {
        match self {
            KdfManager::Hkdf(hkdf) => hkdf.get_kdf_info(),
            KdfManager::Kmac(kmac) => kmac.get_kdf_info(),
        }
    }

    fn derive(
        &self,
        ikm: &[u8],
        info: &[u8],
        length: usize,
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self {
            KdfManager::Hkdf(hkdf) => hkdf.derive(ikm, info, length, salt),
            KdfManager::Kmac(kmac) => kmac.derive(ikm, info, length, salt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::common::kdf_type::KdfType;

    #[test]
    fn test_hkdf_256() {
        let hkdf = KdfManager::new(KdfType::HkdfWithSha256).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"info";
        let length = 32;
        let salt = b"salt";
        let result = hkdf.derive(ikm, info, length, Some(salt)).unwrap();
        assert_eq!(result.len(), length);
    }

    #[test]
    fn test_hkdf_512() {
        let hkdf = KdfManager::new(KdfType::HkdfWithSha512).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"info";
        let length = 64;
        let salt = b"salt";
        let result = hkdf.derive(ikm, info, length, Some(salt)).unwrap();
        assert_eq!(result.len(), length);
    }

    #[test]
    fn test_kmac_128() {
        let kmac = KdfManager::new(KdfType::Kmac128).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"info";
        let length = 16;
        let salt = b"salt";
        let result = kmac.derive(ikm, info, length, Some(salt)).unwrap();
        assert_eq!(result.len(), length);
    }

    #[test]
    fn test_kmac_256() {
        let kmac = KdfManager::new(KdfType::Kmac256).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"info";
        let length = 32;
        let salt = b"salt";
        let result = kmac.derive(ikm, info, length, Some(salt)).unwrap();
        assert_eq!(result.len(), length);
    }
}
