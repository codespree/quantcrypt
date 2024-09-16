use k256::sha2::Sha256;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
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
    rng: ChaCha20Rng,
}

impl Kem for RsaKemManager {
    fn new(kem_type: KemType) -> Self {
        let rng = ChaCha20Rng::from_entropy();
        Self { kem_type, rng }
    }

    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> (Vec<u8>, Vec<u8>) {
        let mut rng = if let Some(seed) = seed {
            ChaCha20Rng::from_seed(*seed)
        } else {
            self.rng.clone()
        };

        let bits = match self.kem_type {
            KemType::RsaOAEP2048 => 2048,
            KemType::RsaOAEP3072 => 3072,
            _ => {
                panic!("Not implemented");
            }
        };

        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);

        (
            pub_key.to_pkcs1_der().unwrap().into_vec(),
            priv_key.to_pkcs1_der().unwrap().as_bytes().to_vec(),
        )
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
        self.rng.fill_bytes(&mut ss);

        let pub_key = RsaPublicKey::from_pkcs1_der(pk)?;

        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ct = pub_key.encrypt(&mut self.rng, padding, &ss).unwrap();
        Ok((ct, ss))
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        // Create a private key from the DER-encoded bytes
        let priv_key = RsaPrivateKey::from_pkcs1_der(sk)?;
        let padding = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
        let ss = priv_key.decrypt(padding, ct)?;
        Ok(ss)
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
