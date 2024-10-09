use crate::cea::aes::Aes;
use crate::cea::common::cea_trait::Cea;
use crate::cea::common::cea_type::CeaType;
use crate::QuantCryptError;

use crate::cea::common::cea_info::CeaInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

const CAE_TYPES: [CeaType; 6] = [
    CeaType::Aes128Gcm,
    CeaType::Aes192Gcm,
    CeaType::Aes256Gcm,
    CeaType::Aes128CbcPad,
    CeaType::Aes192CbcPad,
    CeaType::Aes256CbcPad,
];

// Implement clone
#[derive(Clone)]
/// Enum to representthe different types of KEM managers
pub enum CeaManager {
    /// AES CEA implementation
    Aes(Aes),
}

impl Cea for CeaManager {
    fn new(cae_type: CeaType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match cae_type {
            _ if CAE_TYPES.contains(&cae_type) => CeaManager::Aes(Aes::new(cae_type)?),
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<Vec<u8>> {
        match self {
            CeaManager::Aes(aes) => aes.key_gen(),
        }
    }

    fn get_cea_info(&self) -> CeaInfo {
        match self {
            CeaManager::Aes(aes) => aes.get_cea_info(),
        }
    }

    fn encrypt(
        &self,
        key: &[u8],
        nonce: Option<&[u8]>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        content_type_oid: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            CeaManager::Aes(aes) => aes.encrypt(key, nonce, plaintext, aad, content_type_oid),
        }
    }

    fn decrypt(key: &[u8], tag: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        Aes::decrypt(key, tag, ciphertext, aad)
    }

    fn nonce_gen(&mut self) -> Result<Vec<u8>> {
        match self {
            CeaManager::Aes(aes) => aes.nonce_gen(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cea::common::macros::test_cea;

    #[test]
    fn test_aes() {
        for cae_type in CAE_TYPES.iter() {
            let mut cae = CeaManager::new(cae_type.clone()).unwrap();
            test_cea!(cae);
        }
    }
}
