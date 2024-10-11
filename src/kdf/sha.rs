use crate::kdf::common::kdf_trait::Kdf;
use crate::{kdf::common::kdf_type::KdfType, QuantCryptError};

use super::common::kdf_info::KdfInfo;
use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512};

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Clone)]
pub struct Sha {
    kdf_type: KdfType,
}

impl Kdf for Sha {
    fn new(kdf_type: KdfType) -> Result<Sha> {
        match kdf_type {
            KdfType::Sha3_256 | KdfType::Sha3_512 | KdfType::Sha3_384 => Ok(Sha { kdf_type }),
            _ => Err(QuantCryptError::NotImplemented),
        }
    }

    // ikm, length and salt are assumed to be irrelevant for SHA3
    #[allow(unused_variables)]
    fn derive(
        &self,
        ikm: &[u8],
        info: &[u8],
        length: usize,
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.kdf_type {
            KdfType::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(info);
                Ok(hasher.finalize().to_vec())
            }
            KdfType::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(info);
                Ok(hasher.finalize().to_vec())
            }
            KdfType::Sha3_384 => {
                let mut hasher = Sha3_384::new();
                hasher.update(info);
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(QuantCryptError::NotImplemented),
        }
    }

    fn get_kdf_info(&self) -> super::common::kdf_info::KdfInfo {
        KdfInfo::new(self.kdf_type.clone())
    }
}
