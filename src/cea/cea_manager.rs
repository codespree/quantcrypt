use crate::cea::aes::Aes;
use crate::cea::common::cea_trait::Cea;
use crate::cea::common::cea_type::CeaType;
use crate::QuantCryptError;

use crate::cea::common::cea_info::CeaInfo;

type Result<T> = std::result::Result<T, QuantCryptError>;

const CAE_TYPES: [CeaType; 3] = [CeaType::Aes128Gcm, CeaType::Aes192Gcm, CeaType::Aes256Gcm];

// Implement clone
#[derive(Clone)]
/// Enum to representthe different types of KEM managers
pub enum CaeManager {
    /// AES CEA implementation
    Aes(Aes),
}

impl Cea for CaeManager {
    fn new(cae_type: CeaType) -> Result<Self>
    where
        Self: Sized,
    {
        let result = match cae_type {
            _ if CAE_TYPES.contains(&cae_type) => CaeManager::Aes(Aes::new(cae_type)?),
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };
        Ok(result)
    }

    fn key_gen(&mut self) -> Result<Vec<u8>> {
        match self {
            CaeManager::Aes(aes) => aes.key_gen(),
        }
    }

    fn get_cea_info(&self) -> CeaInfo {
        match self {
            CaeManager::Aes(aes) => aes.get_cea_info(),
        }
    }

    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
        content_type_oid: Option<&str>,
    ) -> Result<Vec<u8>> {
        match self {
            CaeManager::Aes(aes) => aes.encrypt(key, plaintext, aad, content_type_oid),
        }
    }

    fn decrypt(key: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // TODO: Figure out how to handle multiple CEA types
        Aes::decrypt(key, ciphertext, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cea::common::macros::test_cea;

    #[test]
    fn test_aes() {
        for cae_type in CAE_TYPES.iter() {
            let mut cae = CaeManager::new(cae_type.clone()).unwrap();
            test_cea!(cae);
        }
    }
}
