use crate::aead::common::aead_trait::Aead;
use crate::aead::common::aead_type::AeadType;
use crate::QuantCryptError;

use super::common::config::c_max::CMax;
use super::common::config::k_len::KLen;
use super::common::config::n_max::NMAx;
use super::common::config::n_min::NMin;
use super::common::config::p_max::PMax;
use super::common::{aead_info::AeadInfo, config::a_max::AMax};

use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

type Result<T> = std::result::Result<T, QuantCryptError>;

// Implement clone
#[derive(Clone)]
pub struct AesAeadManager {
    aead_type: AeadType,
}

impl Aead for AesAeadManager {
    fn new(aead_type: AeadType) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(AesAeadManager { aead_type })
    }

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.aead_type.get_k_len() {
            return Err(QuantCryptError::InvalidAeadKeyLength);
        }
        if nonce.len() < self.aead_type.get_n_min() || nonce.len() > self.aead_type.get_n_max() {
            return Err(QuantCryptError::InvalidAeadNonceLength);
        }
        if aad.len() > self.aead_type.get_a_max() {
            return Err(QuantCryptError::InvalidAeadAadLength);
        }

        if plaintext.len() > self.aead_type.get_p_max() {
            return Err(QuantCryptError::InvalidAeadPlaintextLength);
        }

        let cipher = match self.aead_type {
            AeadType::AesGcm128 => Cipher::aes_128_gcm(),
            AeadType::AesGcm256 => Cipher::aes_256_gcm(),
        };

        let mut tag = vec![0u8; 16];
        let ct = encrypt_aead(cipher, key, Some(nonce), aad, plaintext, &mut tag)
            .map_err(|_| QuantCryptError::Unknown)?;

        // Combine the ciphertext and tag
        // An AEAD_AES_128_GCM ciphertext is exactly 16 octets longer than its
        // corresponding plaintext.
        let mut result = ct.to_vec();
        result.extend(tag);

        Ok(result)
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.aead_type.get_k_len() {
            return Err(QuantCryptError::InvalidAeadKeyLength);
        }
        if nonce.len() < self.aead_type.get_n_min() || nonce.len() > self.aead_type.get_n_max() {
            return Err(QuantCryptError::InvalidAeadNonceLength);
        }
        if aad.len() > self.aead_type.get_a_max() {
            return Err(QuantCryptError::InvalidAeadAadLength);
        }

        if ciphertext.len() < 16 || ciphertext.len() > self.aead_type.get_c_max() {
            return Err(QuantCryptError::InvalidAeadCiphertextLength);
        }

        let cipher = match self.aead_type {
            AeadType::AesGcm128 => Cipher::aes_128_gcm(),
            AeadType::AesGcm256 => Cipher::aes_256_gcm(),
        };

        let ct_len = ciphertext.len();
        let (ct, tag) = ciphertext.split_at(ct_len - 16);

        let pt = decrypt_aead(cipher, key, Some(nonce), aad, ct, tag)
            .map_err(|_| QuantCryptError::DecryptionFailed)?;

        Ok(pt)
    }

    fn get_aead_info(&self) -> super::common::aead_info::AeadInfo {
        AeadInfo::new(self.aead_type.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::common::aead_type::AeadType;

    #[test]
    fn test_aead_aes_gcm_128() {
        let aes = AesAeadManager::new(AeadType::AesGcm128).unwrap();
        let key = b"0123456789012345";
        let nonce = b"012345678901";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ciphertext = aes.seal(key, nonce, aad, plaintext).unwrap();
        let decrypted = aes.open(key, nonce, aad, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aead_aes_gcm_256() {
        let aes = AesAeadManager::new(AeadType::AesGcm256).unwrap();
        let key = b"01234567890123456789012345678901";
        let nonce = b"012345678901";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ciphertext = aes.seal(key, nonce, aad, plaintext).unwrap();
        let decrypted = aes.open(key, nonce, aad, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aead_aes_gcm_128_invalid_key_length() {
        let aes = AesAeadManager::new(AeadType::AesGcm128).unwrap();
        let key = b"01234567890123456";
        let nonce = b"012345678901";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ct_result = aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadKeyLength,
            ct_result.unwrap_err()
        );

        let key = b"012345678901234";
        let ct_result = aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadKeyLength,
            ct_result.unwrap_err()
        );
    }

    #[test]
    fn test_aead_aes_gcm_128_invalid_nonce_length() {
        let aes = AesAeadManager::new(AeadType::AesGcm128).unwrap();
        let key = b"0123456789012345";
        let nonce = b"0123456789012";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ct_result: std::result::Result<Vec<u8>, QuantCryptError> =
            aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadNonceLength,
            ct_result.unwrap_err()
        );

        let nonce = b"01234567890";
        let ct_result = aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadNonceLength,
            ct_result.unwrap_err()
        );
    }

    #[test]
    fn test_aead_aes_gcm_256_invalid_key_length() {
        let aes = AesAeadManager::new(AeadType::AesGcm128).unwrap();
        let key = b"012345678901234567890123456789012";
        let nonce = b"012345678901";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ct_result = aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadKeyLength,
            ct_result.unwrap_err()
        );

        let key = b"0123456789012345678901234567890";
        let ct_result = aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadKeyLength,
            ct_result.unwrap_err()
        );
    }

    #[test]
    fn test_aead_aes_gcm_256_invalid_nonce_length() {
        let aes = AesAeadManager::new(AeadType::AesGcm256).unwrap();
        let key = b"01234567890123456789012345678901";
        let nonce = b"0123456789012";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ct_result: std::result::Result<Vec<u8>, QuantCryptError> =
            aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadNonceLength,
            ct_result.unwrap_err()
        );

        let nonce = b"01234567890";
        let ct_result = aes.seal(key, nonce, aad, plaintext);
        assert_eq!(
            QuantCryptError::InvalidAeadNonceLength,
            ct_result.unwrap_err()
        );
    }

    #[test]
    fn test_aead_aes_gcm_128_decryption_failed() {
        let aes = AesAeadManager::new(AeadType::AesGcm128).unwrap();
        let key = b"0123456789012345";
        let nonce = b"012345678901";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ciphertext = aes.seal(key, nonce, aad, plaintext).unwrap();

        let key = b"0123456789012302";
        let decrypted = aes.open(key, nonce, aad, &ciphertext);
        assert_eq!(QuantCryptError::DecryptionFailed, decrypted.unwrap_err());

        let key = b"0123456789012345";
        let nonce = b"012345678902";
        let decrypted = aes.open(key, nonce, aad, &ciphertext);
        assert_eq!(QuantCryptError::DecryptionFailed, decrypted.unwrap_err());

        let nonce = b"012345678901";
        let aad = b"012345678901234567890";
        let decrypted = aes.open(key, nonce, aad, &ciphertext);

        assert_eq!(QuantCryptError::DecryptionFailed, decrypted.unwrap_err());
    }

    #[test]
    fn test_aead_aes_gcm_256_decryption_failed() {
        let aes = AesAeadManager::new(AeadType::AesGcm256).unwrap();
        let key = b"01234567890123456789012345678901";
        let nonce = b"012345678901";
        let aad = b"01234567890123456789";
        let plaintext = b"012345678901234567890123456789012345678901234567890123456789";
        let ciphertext = aes.seal(key, nonce, aad, plaintext).unwrap();

        let key = b"01234567890123456789012345678902";
        let decrypted = aes.open(key, nonce, aad, &ciphertext);
        assert_eq!(QuantCryptError::DecryptionFailed, decrypted.unwrap_err());

        let key = b"01234567890123456789012345678901";
        let nonce = b"012345678902";
        let decrypted = aes.open(key, nonce, aad, &ciphertext);
        assert_eq!(QuantCryptError::DecryptionFailed, decrypted.unwrap_err());

        let nonce = b"012345678901";
        let aad = b"012345678901234567890";
        let decrypted = aes.open(key, nonce, aad, &ciphertext);

        assert_eq!(QuantCryptError::DecryptionFailed, decrypted.unwrap_err());
    }
}
