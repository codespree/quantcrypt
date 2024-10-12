use crate::dsa::common::dsa_info::DsaInfo;
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::dsa_type::DsaType;
use crate::QuantCryptError;

use rand_core::SeedableRng;

// When IPD feature is not enabled
#[cfg(not(feature = "ipd"))]
use fips204::ml_dsa_44;
#[cfg(not(feature = "ipd"))]
use fips204::ml_dsa_65;
#[cfg(not(feature = "ipd"))]
use fips204::ml_dsa_87;
#[cfg(not(feature = "ipd"))]
use fips204::traits::{SerDes, Signer, Verifier};

// When IPD feature is enabled
#[cfg(feature = "ipd")]
use fips204_ipd::ml_dsa_44;
#[cfg(feature = "ipd")]
use fips204_ipd::ml_dsa_65;
#[cfg(feature = "ipd")]
use fips204_ipd::ml_dsa_87;
#[cfg(feature = "ipd")]
use fips204_ipd::traits::{SerDes, Signer, Verifier};

type Result<T> = std::result::Result<T, QuantCryptError>;

macro_rules! sign_ml {
    ($ml_type:ident, $sk:expr, $msg:expr) => {{
        if $sk.len() != $ml_type::SK_LEN {
            return Err(QuantCryptError::InvalidPrivateKey);
        }

        // Convert sk to a fixed-size array [u8; SK_LEN]
        let mut sk_buf = [0u8; $ml_type::SK_LEN];
        sk_buf.copy_from_slice($sk);

        // Try to create a private key from the byte array
        let sk = $ml_type::PrivateKey::try_from_bytes(sk_buf)
            .map_err(|_| QuantCryptError::SignatureFailed)?;

        // Try signing the message
        #[cfg(feature = "ipd")]
        let sig = sk
            .try_sign($msg)
            .map_err(|_| QuantCryptError::SignatureFailed)?;
        #[cfg(not(feature = "ipd"))]
        let sig = sk
            .try_sign($msg, &[]) // Empty context
            .map_err(|_| QuantCryptError::SignatureFailed)?;

        // Convert the signature to a Vec<u8> and return it
        let sig: Vec<u8> = sig.to_vec();
        Ok(sig)
    }};
}

macro_rules! verify_ml {
    ($ml_type:ident, $pk: expr, $msg: expr, $signature: expr) => {{
        if $pk.len() != $ml_type::PK_LEN {
            return Err(QuantCryptError::InvalidPublicKey);
        }

        if $signature.len() != $ml_type::SIG_LEN {
            return Err(QuantCryptError::InvalidSignature);
        }

        // Convert pk to [u8; 1312]
        let mut pk_buf = [0u8; $ml_type::PK_LEN];
        pk_buf.copy_from_slice($pk);

        let mut sig_buf = [0u8; $ml_type::SIG_LEN];
        sig_buf.copy_from_slice($signature);

        let pk = $ml_type::PublicKey::try_from_bytes(pk_buf)
            .map_err(|_| QuantCryptError::InvalidPublicKey)?;

        #[cfg(feature = "ipd")]
        let result = Ok(pk.verify($msg, &sig_buf));

        #[cfg(not(feature = "ipd"))]
        let result = Ok(pk.verify($msg, &sig_buf, &[]));

        result
    }};
}

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
    fn new(dsa_type: DsaType) -> Result<Self> {
        let dsa_info = DsaInfo::new(dsa_type);
        Ok(Self { dsa_info })
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
                let (pk, sk) = ml_dsa_44::try_keygen_with_rng(rng)
                    .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
                let pk = pk.into_bytes().to_vec();
                let sk = sk.into_bytes().to_vec();
                Ok((pk, sk))
            }
            DsaType::MlDsa65 => {
                let (pk, sk) = ml_dsa_65::try_keygen_with_rng(rng)
                    .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
                let pk = pk.into_bytes().to_vec();
                let sk = sk.into_bytes().to_vec();
                Ok((pk, sk))
            }
            DsaType::MlDsa87 => {
                let (pk, sk) = ml_dsa_87::try_keygen_with_rng(rng)
                    .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;
                let pk = pk.into_bytes().to_vec();
                let sk = sk.into_bytes().to_vec();
                Ok((pk, sk))
            }
            _ => Err(QuantCryptError::NotImplemented),
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
            DsaType::MlDsa44 => sign_ml!(ml_dsa_44, sk, msg),
            DsaType::MlDsa65 => sign_ml!(ml_dsa_65, sk, msg),
            DsaType::MlDsa87 => sign_ml!(ml_dsa_87, sk, msg),
            _ => Err(QuantCryptError::NotImplemented),
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
                verify_ml!(ml_dsa_44, pk, msg, signature)
            }
            DsaType::MlDsa65 => {
                verify_ml!(ml_dsa_65, pk, msg, signature)
            }
            DsaType::MlDsa87 => {
                verify_ml!(ml_dsa_87, pk, msg, signature)
            }
            _ => Err(QuantCryptError::NotImplemented),
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
    use super::*;
    use crate::dsa::common::dsa_type::DsaType;
    use crate::dsa::common::macros::test_dsa;

    #[test]
    fn test_ml_dsa_44() {
        let dsa = MlDsaManager::new(DsaType::MlDsa44);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ml_dsa_65() {
        let dsa = MlDsaManager::new(DsaType::MlDsa65);
        test_dsa!(dsa);
    }

    #[test]
    fn test_ml_dsa_87() {
        let dsa = MlDsaManager::new(DsaType::MlDsa87);
        test_dsa!(dsa);
    }
}
