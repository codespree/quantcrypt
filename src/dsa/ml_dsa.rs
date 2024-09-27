use crate::dsa::common::dsa_info::DsaInfo;
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::dsa_type::DsaType;
use fips204::traits::{SerDes, Signer, Verifier};
use rand_core::SeedableRng;

use std::error;

use fips204::ml_dsa_44;
use fips204::ml_dsa_65;
use fips204::ml_dsa_87;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Clone)]
pub struct MlDsaManager {
    pub dsa_info: DsaInfo,
}

impl Dsa for MlDsaManager {
    /// Create a new DSA instance
    ///
    /// # Arguments
    ///
    /// * `dsa_type` - The type of DSA to create
    fn new(dsa_type: DsaType) -> Self {
        let dsa_info = DsaInfo::new(dsa_type);
        Self { dsa_info }
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
    fn key_gen_with_rng(
        &mut self,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.dsa_info.dsa_type {
            DsaType::MlDsa44 => {
                let (pk, sk) = ml_dsa_44::try_keygen_with_rng(rng)?;
                let pk = pk.into_bytes().to_vec();
                let sk = sk.into_bytes().to_vec();
                Ok((pk, sk))
            }
            DsaType::MlDsa65 => {
                let (pk, sk) = ml_dsa_65::try_keygen_with_rng(rng)?;
                let pk = pk.into_bytes().to_vec();
                let sk = sk.into_bytes().to_vec();
                Ok((pk, sk))
            }
            DsaType::MlDsa87 => {
                let (pk, sk) = ml_dsa_87::try_keygen_with_rng(rng)?;
                let pk = pk.into_bytes().to_vec();
                let sk = sk.into_bytes().to_vec();
                Ok((pk, sk))
            }
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Generate a keypair using the default RNG ChaCha20Rng
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        self.key_gen_with_rng(&mut rng)
    }

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to sign
    /// * `sk` - The secret key
    ///
    /// # Returns
    ///
    /// The signature
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        match self.dsa_info.dsa_type {
            DsaType::MlDsa44 => {
                // Convert sk to [u8; 2560]
                let mut sk_buf = [0u8; 2560];
                sk_buf.copy_from_slice(sk);

                let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_buf)?;
                let sig = sk.try_sign(msg)?;
                let sig: Vec<u8> = sig.to_vec();
                Ok(sig)
            }
            DsaType::MlDsa65 => {
                // Convert sk to [u8; 2560]
                let mut sk_buf = [0u8; 4032];
                sk_buf.copy_from_slice(sk);

                let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_buf)?;
                let sig = sk.try_sign(msg)?;
                let sig: Vec<u8> = sig.to_vec();
                Ok(sig)
            }
            DsaType::MlDsa87 => {
                // Convert sk to [u8; 2560]
                let mut sk_buf = [0u8; 4896];
                sk_buf.copy_from_slice(sk);

                let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_buf)?;
                let sig = sk.try_sign(msg)?;
                let sig: Vec<u8> = sig.to_vec();
                Ok(sig)
            }
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to verify
    /// * `pk` - The public key
    /// * `sig` - The signature
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid
    fn verify(&self, pk: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
        match self.dsa_info.dsa_type {
            DsaType::MlDsa44 => {
                // TODO: These conversions can panic, fix it later
                // Convert pk to [u8; 1312]
                let mut pk_buf = [0u8; 1312];
                pk_buf.copy_from_slice(pk);

                let mut sig_buf = [0u8; 2420];
                sig_buf.copy_from_slice(signature);

                let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_buf)?;
                Ok(pk.verify(msg, &sig_buf))
            }
            DsaType::MlDsa65 => {
                // Convert pk to [u8; 1312]
                let mut pk_buf = [0u8; 1952];
                pk_buf.copy_from_slice(pk);

                let mut sig_buf = [0u8; 3309];
                sig_buf.copy_from_slice(signature);

                let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_buf)?;
                Ok(pk.verify(msg, &sig_buf))
            }
            DsaType::MlDsa87 => {
                // Convert pk to [u8; 1312]
                let mut pk_buf = [0u8; 2592];
                pk_buf.copy_from_slice(pk);

                let mut sig_buf = [0u8; 4627];
                sig_buf.copy_from_slice(signature);

                let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_buf)?;
                Ok(pk.verify(msg, &sig_buf))
            }
            _ => {
                panic!("Not implemented");
            }
        }
    }

    /// Get DSA metadata information such as the key lengths,
    /// size of signature, etc.
    fn get_dsa_info(&self) -> DsaInfo {
        self.dsa_info.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::asn1::composite_public_key::PublicKeyInfo;
    use der::{Decode, DecodePem, Encode};
    use x509_cert::Certificate;

    use super::*;
    use crate::dsa::common::dsa_type::DsaType;
    use crate::dsa::common::macros::test_dsa;

    #[test]
    fn test_ml_dsa_44() {
        let mut dsa = MlDsaManager::new(DsaType::MlDsa44);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ml_dsa_65() {
        let mut dsa = MlDsaManager::new(DsaType::MlDsa65);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ml_dsa_87() {
        let mut dsa = MlDsaManager::new(DsaType::MlDsa87);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ml_dsa_44_cert() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_self_signed.pem");
        let dsa = MlDsaManager::new(DsaType::MlDsa44);
        let cert = Certificate::from_pem(pem_bytes).unwrap();
        let cert_pub_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let spki = PublicKeyInfo::from_der(&cert_pub_key).unwrap();
        let sig = cert.signature.as_bytes().unwrap();
        let msg = cert.tbs_certificate.to_der().unwrap();
        let cert_pub_key = spki.public_key.as_bytes().unwrap();
        let is_verified = dsa.verify(&cert_pub_key, &msg, &sig).unwrap();
        assert!(is_verified);
    }
}
