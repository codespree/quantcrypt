use crate::dsa::common::dsa_info::DsaInfo;
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::dsa_type::DsaType;
use crate::QuantCryptError;

use rand_core::SeedableRng;

// When IPD feature is not enabled
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_sha2_128f;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_sha2_128s;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_sha2_192f;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_sha2_192s;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_sha2_256f;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_sha2_256s;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_shake_128f;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_shake_128s;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_shake_192f;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_shake_192s;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_shake_256f;
#[cfg(not(feature = "ipd"))]
use fips205::slh_dsa_shake_256s;
#[cfg(not(feature = "ipd"))]
use fips205::traits::{SerDes, Signer, Verifier};

type Result<T> = std::result::Result<T, QuantCryptError>;

macro_rules! sign_slh {
    ($sig_type:ident, $sk:expr, $msg:expr) => {{
        if $sk.len() != $sig_type::SK_LEN {
            return Err(QuantCryptError::InvalidPrivateKey);
        }

        // Convert sk to a fixed-size array [u8; SK_LEN]
        let mut sk_buf = [0u8; $sig_type::SK_LEN];
        sk_buf.copy_from_slice($sk);

        // Try to create a private key from the byte array
        let sk = $sig_type::PrivateKey::try_from_bytes(&sk_buf)
            .map_err(|_| QuantCryptError::SignatureFailed)?;

        // Try signing the message
        let sig = sk
            .try_sign($msg, &[], true) // Empty context
            .map_err(|_| QuantCryptError::SignatureFailed)?;

        // Convert the signature to a Vec<u8> and return it
        let sig: Vec<u8> = sig.to_vec();
        Ok(sig)
    }};
}

macro_rules! verify_slh {
    ($sig_type:ident, $pk: expr, $msg: expr, $signature: expr) => {{
        if $pk.len() != $sig_type::PK_LEN {
            return Err(QuantCryptError::InvalidPublicKey);
        }

        if $signature.len() != $sig_type::SIG_LEN {
            return Err(QuantCryptError::InvalidSignature);
        }

        // Convert pk to [u8; 1312]
        let mut pk_buf = [0u8; $sig_type::PK_LEN];
        pk_buf.copy_from_slice($pk);

        let mut sig_buf = [0u8; $sig_type::SIG_LEN];
        sig_buf.copy_from_slice($signature);

        let pk = $sig_type::PublicKey::try_from_bytes(&pk_buf)
            .map_err(|_| QuantCryptError::InvalidPublicKey)?;

        let result = Ok(pk.verify($msg, &sig_buf, &[]));

        result
    }};
}

macro_rules! keygen_slh {
    ($sig_type:ident, $rng: expr) => {{
        let (pk, sk) = $sig_type::try_keygen_with_rng($rng)
            .map_err(|_| QuantCryptError::KeyPairGenerationFailed)?;

        let pk = pk.into_bytes().to_vec();
        let sk = sk.into_bytes().to_vec();
        Ok((pk, sk))
    }};
}

#[derive(Clone)]
pub struct SlhDsaManager {
    pub dsa_info: DsaInfo,
}

impl Dsa for SlhDsaManager {
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
            DsaType::SlhDsaSha2_128s => keygen_slh!(slh_dsa_sha2_128s, rng),
            DsaType::SlhDsaSha2_128f => keygen_slh!(slh_dsa_sha2_128f, rng),
            DsaType::SlhDsaSha2_192s => keygen_slh!(slh_dsa_sha2_192s, rng),
            DsaType::SlhDsaSha2_192f => keygen_slh!(slh_dsa_sha2_192f, rng),
            DsaType::SlhDsaSha2_256s => keygen_slh!(slh_dsa_sha2_256s, rng),
            DsaType::SlhDsaSha2_256f => keygen_slh!(slh_dsa_sha2_256f, rng),
            DsaType::SlhDsaShake128s => keygen_slh!(slh_dsa_shake_128s, rng),
            DsaType::SlhDsaShake128f => keygen_slh!(slh_dsa_shake_128f, rng),
            DsaType::SlhDsaShake192s => keygen_slh!(slh_dsa_shake_192s, rng),
            DsaType::SlhDsaShake192f => keygen_slh!(slh_dsa_shake_192f, rng),
            DsaType::SlhDsaShake256s => keygen_slh!(slh_dsa_shake_256s, rng),
            DsaType::SlhDsaShake256f => keygen_slh!(slh_dsa_shake_256f, rng),
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
            DsaType::SlhDsaSha2_128s => sign_slh!(slh_dsa_sha2_128s, &sk, msg),
            DsaType::SlhDsaSha2_128f => sign_slh!(slh_dsa_sha2_128f, &sk, msg),
            DsaType::SlhDsaSha2_192s => sign_slh!(slh_dsa_sha2_192s, &sk, msg),
            DsaType::SlhDsaSha2_192f => sign_slh!(slh_dsa_sha2_192f, &sk, msg),
            DsaType::SlhDsaSha2_256s => sign_slh!(slh_dsa_sha2_256s, &sk, msg),
            DsaType::SlhDsaSha2_256f => sign_slh!(slh_dsa_sha2_256f, &sk, msg),
            DsaType::SlhDsaShake128s => sign_slh!(slh_dsa_shake_128s, &sk, msg),
            DsaType::SlhDsaShake128f => sign_slh!(slh_dsa_shake_128f, &sk, msg),
            DsaType::SlhDsaShake192s => sign_slh!(slh_dsa_shake_192s, &sk, msg),
            DsaType::SlhDsaShake192f => sign_slh!(slh_dsa_shake_192f, &sk, msg),
            DsaType::SlhDsaShake256s => sign_slh!(slh_dsa_shake_256s, &sk, msg),
            DsaType::SlhDsaShake256f => sign_slh!(slh_dsa_shake_256f, &sk, msg),
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
            DsaType::SlhDsaSha2_128f => verify_slh!(slh_dsa_sha2_128f, pk, msg, signature),
            DsaType::SlhDsaSha2_128s => verify_slh!(slh_dsa_sha2_128s, pk, msg, signature),
            DsaType::SlhDsaSha2_192f => verify_slh!(slh_dsa_sha2_192f, pk, msg, signature),
            DsaType::SlhDsaSha2_192s => verify_slh!(slh_dsa_sha2_192s, pk, msg, signature),
            DsaType::SlhDsaSha2_256f => verify_slh!(slh_dsa_sha2_256f, pk, msg, signature),
            DsaType::SlhDsaSha2_256s => verify_slh!(slh_dsa_sha2_256s, pk, msg, signature),
            DsaType::SlhDsaShake128f => verify_slh!(slh_dsa_shake_128f, pk, msg, signature),
            DsaType::SlhDsaShake128s => verify_slh!(slh_dsa_shake_128s, pk, msg, signature),
            DsaType::SlhDsaShake192f => verify_slh!(slh_dsa_shake_192f, pk, msg, signature),
            DsaType::SlhDsaShake192s => verify_slh!(slh_dsa_shake_192s, pk, msg, signature),
            DsaType::SlhDsaShake256f => verify_slh!(slh_dsa_shake_256f, pk, msg, signature),
            DsaType::SlhDsaShake256s => verify_slh!(slh_dsa_shake_256s, pk, msg, signature),
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
    use crate::certificates::Certificate;
    use crate::dsa::common::dsa_type::DsaType;
    use crate::dsa::common::macros::test_dsa;

    #[test]
    fn test_slh_dsa_sha2_128s() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaSha2_128s);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-sha2-128s-2.16.840.1.101.3.4.3.20_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_sha2_128f() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaSha2_128f);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-sha2-128f-2.16.840.1.101.3.4.3.21_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_sha2_192s() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaSha2_192s);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-sha2-192s-2.16.840.1.101.3.4.3.22_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_sha2_192f() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaSha2_192f);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-sha2-192f-2.16.840.1.101.3.4.3.23_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_sha2_256s() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaSha2_256s);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-sha2-256s-2.16.840.1.101.3.4.3.24_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_sha2_256f() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaSha2_256f);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-sha2-256f-2.16.840.1.101.3.4.3.25_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_shake_128s() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaShake128s);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-shake-128s-2.16.840.1.101.3.4.3.26_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_shake_128f() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaShake128f);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-shake-128f-2.16.840.1.101.3.4.3.27_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_shake_192s() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaShake192s);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-shake-192s-2.16.840.1.101.3.4.3.28_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_shake_192f() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaShake192f);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-shake-192f-2.16.840.1.101.3.4.3.29_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_shake_256s() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaShake256s);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-shake-256s-2.16.840.1.101.3.4.3.30_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_shake_256f() {
        let dsa = SlhDsaManager::new(DsaType::SlhDsaShake256f);
        test_dsa!(dsa);

        #[cfg(not(feature = "ipd"))]
        {
            let cert_bytes = include_bytes!(
                "../../test/data/slh/slh-dsa-shake-256f-2.16.840.1.101.3.4.3.31_ta.der"
            );
            let cert = Certificate::from_der(cert_bytes).unwrap();
            assert!(cert.verify_self_signed().unwrap());
        }
    }
}
