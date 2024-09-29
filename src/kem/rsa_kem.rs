use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use sha2::Sha256;

use crate::kem::common::kem_trait::Kem;
use crate::kem::common::kem_type::KemType;
use crate::{kem::common::kem_info::KemInfo, QuantCryptError};
use rsa::{
    oaep::Oaep,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A KEM manager for the RSA-KEM method
pub struct RsaKemManager {
    kem_info: KemInfo,
}

impl Kem for RsaKemManager {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    ///
    /// # Returns
    ///
    /// A new KEM instance
    fn new(kem_type: KemType) -> Result<Self> {
        let kem_info = KemInfo::new(kem_type);
        Ok(Self { kem_info })
    }

    /// Generate a keypair using the specified RNG
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk).
    /// Both keys are in PKCS1 DER format.
    fn key_gen_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>)> {
        let bits = match self.kem_info.kem_type {
            KemType::RsaOAEP2048 => 2048,
            KemType::RsaOAEP3072 => 3072,
            KemType::RsaOAEP4096 => 4096,
            _ => {
                return Err(QuantCryptError::NotImplemented);
            }
        };

        // Use the RSA crate as we can specify the rng
        let rpk =
            RsaPrivateKey::new(rng, bits).map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        let sd = rpk
            .to_pkcs1_der()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
        let sk = sd.to_bytes().to_vec();

        // PKCS1 DER format
        let pd = rpk
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
        let pk = pd.to_vec();

        Ok((pk, sk))
    }

    /// Generate a keypair using the default RNG ChaCha20Rng
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = ChaCha20Rng::from_entropy();
        self.key_gen_with_rng(&mut rng)
    }

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the shared secret and ciphertext (ss, ct)
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        /*
        +====================+===================================+
        | RSA-OAEP Parameter | Value                             |
        +====================+===================================+
        | hashFunc           | id-sha2-256                       |
        +--------------------+-----------------------------------+
        | maskGenFunc        | mgf1SHA256Identifier              |
        +--------------------+-----------------------------------+
        | pSourceFunc        | DEFAULT pSpecifiedEmptyIdentifier |
        +--------------------+-----------------------------------+
        | ss_len             | 256 bits                          |
        +--------------------+-----------------------------------+
         */
        // Generate a shared secret (32 bits)
        let mut ss = vec![0u8; 32];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut ss);

        let pub_key =
            RsaPublicKey::from_pkcs1_der(pk).map_err(|_| QuantCryptError::InvalidPublicKey)?;
        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ct = pub_key
            .encrypt(&mut rng, padding, &ss)
            .map_err(|_| QuantCryptError::EncapFailed)?;
        Ok((ss, ct))
    }

    /// Decapsulate a ciphertext
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to decapsulate with
    /// * `ct` - The ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The shared secret (ss)
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        // Create a private key from the DER-encoded bytes
        let priv_key =
            RsaPrivateKey::from_pkcs1_der(sk).map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ss = priv_key
            .decrypt(padding, ct)
            .map_err(|_| QuantCryptError::DecapFailed)?;
        Ok(ss)
    }

    /// Get KEM metadata information such as the key lengths,
    /// size of ciphertext, etc.
    ///
    /// These values are also used to test the correctness of the KEM
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the KEM
    fn get_kem_info(&self) -> KemInfo {
        self.kem_info.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::common::kem_type::KemType;
    use crate::kem::common::macros::test_kem;

    #[test]
    fn test_rsa_kem_2048() {
        let kem = RsaKemManager::new(KemType::RsaOAEP2048);
        test_kem!(kem);
    }

    #[test]
    fn test_rsa_kem_3072() {
        let kem = RsaKemManager::new(KemType::RsaOAEP3072);
        test_kem!(kem);
    }

    #[test]
    fn test_rsa_kem_4096() {
        let kem = RsaKemManager::new(KemType::RsaOAEP4096);
        test_kem!(kem);
    }
}
