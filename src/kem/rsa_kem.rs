use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha256;
use std::error;

use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use rsa::{
    oaep::Oaep,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// A KEM manager for the RSA-KEM method
pub struct RsaKemManager {
    kem_type: KemType,
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
    fn new(kem_type: KemType) -> Self {
        Self { kem_type }
    }

    /// Generate a keypair
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(*seed)
        } else {
            ChaCha20Rng::from_entropy()
        };

        let bits = match self.kem_type {
            KemType::RsaOAEP2048 => 2048,
            KemType::RsaOAEP3072 => 3072,
            KemType::RsaOAEP4096 => 4096,
            _ => {
                panic!("Not implemented");
            }
        };

        // Use the RSA crate as we can specify the rng
        let rpk: RsaPrivateKey = RsaPrivateKey::new(&mut rng, bits)?;
        let sd = rpk.to_pkcs1_der()?;
        let sk = sd.to_bytes().to_vec();

        // PKCS1 DER format
        let pd = rpk.to_public_key().to_pkcs1_der()?;
        let pk = pd.to_vec();

        Ok((pk, sk))
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

        let pub_key = RsaPublicKey::from_pkcs1_der(pk)?;
        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ct = pub_key.encrypt(&mut rng, padding, &ss)?;
        Ok((ss, ct))
    }

    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        // Create a private key from the DER-encoded bytes
        let priv_key = RsaPrivateKey::from_pkcs1_der(sk)?;
        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ss = priv_key.decrypt(padding, ct)?;
        Ok(ss)
    }

    /// Get the length of the shared secret in bytes
    ///
    /// # Returns
    ///
    /// The length of the shared secret in bytes
    fn get_ss_byte_len(&self) -> usize {
        32
    }

    /// Get the type of KEM
    ///
    /// # Returns
    ///
    /// The type of KEM
    fn get_kem_type(&self) -> KemType {
        self.kem_type.clone()
    }

    /// Get the length of the ciphertext in bytes
    /// (for the encaps method)
    ///
    /// # Returns
    ///
    /// The length of the ciphertext in bytes
    fn get_ct_byte_len(&self) -> Option<usize> {
        match self.kem_type {
            KemType::RsaOAEP2048 => Some(256),
            KemType::RsaOAEP3072 => Some(384),
            KemType::RsaOAEP4096 => Some(512),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Get the length of the public key in bytes
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes
    fn get_pk_byte_len(&self) -> Option<usize> {
        None
    }

    /// Get the length of the secret key in bytes
    ///
    /// # Returns
    ///
    /// The length of the secret key in bytes
    fn get_sk_byte_len(&self) -> Option<usize> {
        None
    }

    fn get_oid(&self) -> String {
        match self.kem_type {
            //TODO: Confirm the OID for RSA-OAEP
            KemType::RsaOAEP2048 => "1.2.840.113549.1.1.7".to_string(),
            KemType::RsaOAEP3072 => "1.2.840.113549.1.1.7".to_string(),
            KemType::RsaOAEP4096 => "1.2.840.113549.1.1.7".to_string(),
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Get the public key given a secret key
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key
    ///
    /// # Returns
    ///
    /// The public key
    fn get_pk(&self, sk: &[u8]) -> Result<Vec<u8>> {
        let sk = RsaPrivateKey::from_pkcs1_der(sk)?;
        Ok(sk.to_public_key().to_pkcs1_der()?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::kem_type::KemType;
    use crate::kem::macros::test_kem;

    #[test]
    fn test_rsa_kem_2048() {
        let mut kem = RsaKemManager::new(KemType::RsaOAEP2048);
        test_kem!(kem);
    }

    #[test]
    fn test_rsa_kem_3072() {
        let mut kem = RsaKemManager::new(KemType::RsaOAEP3072);
        test_kem!(kem);
    }

    #[test]
    fn test_rsa_kem_4096() {
        let mut kem = RsaKemManager::new(KemType::RsaOAEP4096);
        test_kem!(kem);
    }

    #[test]
    fn test_get_pk_from_sk() {
        let kem_types = vec![
            KemType::RsaOAEP2048,
            KemType::RsaOAEP3072,
            KemType::RsaOAEP4096,
        ];

        for kem_type in kem_types {
            let mut kem = RsaKemManager::new(kem_type);
            let (pk, sk) = kem.key_gen(None).unwrap();
            let pk2 = kem.get_pk(&sk).unwrap();
            assert_eq!(pk, pk2);
        }
    }
}
