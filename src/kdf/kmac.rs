// https://datatracker.ietf.org/doc/rfc9629/

use crate::kdf::common::kdf_trait::Kdf;
use crate::{kdf::common::kdf_type::KdfType, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;
use tiny_keccak::{Hasher, Kmac as KmacKeccak};

use crate::kdf::common::kdf_info::KdfInfo;

#[derive(Clone)]
pub struct Kmac {
    kdf_type: KdfType,
}

impl Kdf for Kmac {
    fn new(kdf_type: KdfType) -> Result<Kmac> {
        match kdf_type {
            KdfType::Kmac128 | KdfType::Kmac256 => Ok(Kmac { kdf_type }),
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
        let salt = if let Some(salt) = salt { salt } else { &[] };
        match self.kdf_type {
            KdfType::Kmac128 => {
                let mut kmac = KmacKeccak::v128(ikm, salt);
                kmac.update(info);
                let mut okm: Vec<u8> = vec![0; length];
                kmac.finalize(&mut okm);
                Ok(okm)
            }
            KdfType::Kmac256 => {
                let mut kmac = KmacKeccak::v256(ikm, salt);
                kmac.update(info);
                let mut okm: Vec<u8> = vec![0; length];
                kmac.finalize(&mut okm);
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
    fn test_kmac_128() {
        let kmac = Kmac::new(KdfType::Kmac128).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"01234567890123456789";
        let length = 0;
        let salt = b"0123456789012345";
        let okm = kmac.derive(ikm, info, length, Some(salt)).unwrap();
        assert_eq!(okm.len(), length);
    }

    #[test]
    fn test_kmac_256() {
        let kmac = Kmac::new(KdfType::Kmac256).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"01234567890123456789";
        let length = 0;
        let salt = b"0123456789012345";
        let okm = kmac.derive(ikm, info, length, Some(salt)).unwrap();
        assert_eq!(okm.len(), length);
    }
}
