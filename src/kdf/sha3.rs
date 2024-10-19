// https://datatracker.ietf.org/doc/rfc9629/

use std::io::Write;

use crate::kdf::common::kdf_trait::Kdf;
use crate::{kdf::common::kdf_type::KdfType, QuantCryptError};

use super::common::kdf_info::KdfInfo;
use signature::digest::ExtendableOutput;
use std::io::Read;

type Result<T> = std::result::Result<T, QuantCryptError>;

macro_rules! derive_key {
    ($shake:expr, $ikm:expr, $info:expr, $length:expr, $salt:expr) => {{
        // If salt is provided, absorb it first
        if let Some(s) = $salt {
            $shake.write(s).map_err(|_| QuantCryptError::KdfError)?;
        }

        // Absorb the input keying material (ikm)
        $shake.write($ikm).map_err(|_| QuantCryptError::KdfError)?;

        // Optionally absorb the context-specific information
        if $info.len() > 0 {
            $shake.write($info).map_err(|_| QuantCryptError::KdfError)?;
        }

        // Finalize and create a reader to generate output bytes
        let mut reader = $shake.finalize_xof();

        // Read the derived key of the specified length
        let mut derived_key = vec![0u8; $length];
        reader
            .read_exact(&mut derived_key)
            .map_err(|_| QuantCryptError::KdfError)?;

        Ok(derived_key)
    }};
}

#[derive(Clone)]
pub struct Sha3Kdf {
    kdf_type: KdfType,
}

impl Kdf for Sha3Kdf {
    fn new(kdf_type: KdfType) -> Result<Sha3Kdf> {
        match kdf_type {
            KdfType::Shake128 | KdfType::Shake256 => Ok(Sha3Kdf { kdf_type }),
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
            KdfType::Shake128 => {
                let mut shake = sha3::Shake128::default();
                derive_key!(shake, ikm, info, length, salt)
            }
            KdfType::Shake256 => {
                let mut shake = sha3::Shake256::default();
                derive_key!(shake, ikm, info, length, salt)
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
    fn test_shake_128() {
        let shake = Sha3Kdf::new(KdfType::Shake128).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"01234567890123456789";
        let length = 0;

        let okm = shake.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);

        let length = 64;
        let okm = shake.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);

        // Check with empty info
        let info = b"";
        let okm = shake.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);
    }

    #[test]
    fn test_shake_256() {
        let shake = Sha3Kdf::new(KdfType::Shake256).unwrap();
        let ikm = b"012345678901234567890123456789012345678901234567890123456789";
        let info = b"01234567890123456789";
        let length = 0;

        let okm = shake.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);

        let length = 64;
        let okm = shake.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);

        // Check with empty info
        let info = b"";
        let okm = shake.derive(ikm, info, length, None).unwrap();
        assert_eq!(okm.len(), length);
    }
}
