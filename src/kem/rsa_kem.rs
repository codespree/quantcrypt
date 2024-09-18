use openssl::pkey::PKey;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha256;
use std::error;

use crate::kem::kem_trait::Kem;
use crate::kem::kem_type::KemType;
use rsa::{
    oaep::Oaep,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey},
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

    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(*seed)
        } else {
            ChaCha20Rng::from_entropy()
        };

        let bits = match self.kem_type {
            KemType::RsaOAEP2048 => 2048,
            KemType::RsaOAEP3072 => 3072,
            _ => {
                panic!("Not implemented");
            }
        };

        // Use the RSA crate as we can specify the rng
        let sk = RsaPrivateKey::new(&mut rng, bits)?;
        let sd = sk.to_pkcs1_der()?;

        // PKCS1 DER format is compatible with OpenSSL
        let sk = sd.as_bytes();

        // Ensure compatibility with OpenSSL by creating a PKey object
        let sk = PKey::from_rsa(openssl::rsa::Rsa::private_key_from_der(sk)?)?;

        // Return keys in the SPKI format of OpenSSL
        let pk = sk.public_key_to_der()?;
        let sk = sk.private_key_to_der()?;

        Ok((pk, sk))
    }

    fn encaps(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
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

        let pk_obj = PKey::from_rsa(openssl::rsa::Rsa::public_key_from_der(pk)?)?;

        // Extract the RSA public key from the PKey<Public>
        let rsa = pk_obj.rsa()?;

        // Serialize the RSA public key to PKCS#1 DER format
        // This converts it from SPKI to PKCS#1
        let pkcs1_der = rsa.public_key_to_der_pkcs1()?;

        let pub_key = RsaPublicKey::from_pkcs1_der(&pkcs1_der)?;
        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ct = pub_key.encrypt(&mut rng, padding, &ss)?;
        Ok((ct, ss))
    }

    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
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
}
