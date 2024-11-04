use crate::QuantCryptError;

use rand_core::SeedableRng;

// When IPD feature is not enabled
use fips205::slh_dsa_sha2_128f;
use fips205::slh_dsa_sha2_128s;
use fips205::slh_dsa_sha2_192f;
use fips205::slh_dsa_sha2_192s;
use fips205::slh_dsa_sha2_256f;
use fips205::slh_dsa_sha2_256s;
use fips205::slh_dsa_shake_128f;
use fips205::slh_dsa_shake_128s;
use fips205::slh_dsa_shake_192f;
use fips205::slh_dsa_shake_192s;
use fips205::slh_dsa_shake_256f;
use fips205::slh_dsa_shake_256s;
use fips205::traits::{SerDes, Signer, Verifier};

use super::common::prehash_dsa_info::PrehashDsaInfo;
use super::common::prehash_dsa_trait::PrehashDsa;
use super::common::prehash_dsa_type::PrehashDsaType;

type Result<T> = std::result::Result<T, QuantCryptError>;

macro_rules! sign_slh {
    ($sig_type:ident, $sk:expr, $msg:expr, $ctx:expr) => {{
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
            .try_sign($msg, $ctx, true)
            .map_err(|_| QuantCryptError::SignatureFailed)?;

        // Convert the signature to a Vec<u8> and return it
        let sig: Vec<u8> = sig.to_vec();
        Ok(sig)
    }};
}

macro_rules! verify_slh {
    ($sig_type:ident, $pk: expr, $msg: expr, $signature: expr, $ctx: expr) => {{
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

        let result = Ok(pk.verify($msg, &sig_buf, $ctx));

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

macro_rules! get_public_key {
    ($sig_type:ident, $sk:expr) => {{
        if $sk.len() != $sig_type::SK_LEN {
            return Err(QuantCryptError::InvalidPrivateKey);
        }
        let mut sk_buf = [0u8; $sig_type::SK_LEN];
        sk_buf.copy_from_slice($sk);
        let pk = $sig_type::PrivateKey::try_from_bytes(&sk_buf)
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(pk.get_public_key().into_bytes().to_vec())
    }};
}

#[derive(Clone)]
pub struct SlhDsaManager {
    pub dsa_info: PrehashDsaInfo,
}

impl PrehashDsa for SlhDsaManager {
    /// Create a new DSA instance
    ///
    /// # Arguments
    ///
    /// * `dsa_type` - The type of DSA to create
    fn new(dsa_type: PrehashDsaType) -> Result<Self> {
        let dsa_info = PrehashDsaInfo::new(dsa_type);
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
            PrehashDsaType::SlhDsaSha2_128s => keygen_slh!(slh_dsa_sha2_128s, rng),
            PrehashDsaType::SlhDsaSha2_128f => keygen_slh!(slh_dsa_sha2_128f, rng),
            PrehashDsaType::SlhDsaSha2_192s => keygen_slh!(slh_dsa_sha2_192s, rng),
            PrehashDsaType::SlhDsaSha2_192f => keygen_slh!(slh_dsa_sha2_192f, rng),
            PrehashDsaType::SlhDsaSha2_256s => keygen_slh!(slh_dsa_sha2_256s, rng),
            PrehashDsaType::SlhDsaSha2_256f => keygen_slh!(slh_dsa_sha2_256f, rng),
            PrehashDsaType::SlhDsaShake128s => keygen_slh!(slh_dsa_shake_128s, rng),
            PrehashDsaType::SlhDsaShake128f => keygen_slh!(slh_dsa_shake_128f, rng),
            PrehashDsaType::SlhDsaShake192s => keygen_slh!(slh_dsa_shake_192s, rng),
            PrehashDsaType::SlhDsaShake192f => keygen_slh!(slh_dsa_shake_192f, rng),
            PrehashDsaType::SlhDsaShake256s => keygen_slh!(slh_dsa_shake_256s, rng),
            PrehashDsaType::SlhDsaShake256f => keygen_slh!(slh_dsa_shake_256f, rng),
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

    /// Get DSA metadata information such as the key lengths,
    /// size of signature, etc.
    fn get_dsa_info(&self) -> PrehashDsaInfo {
        self.dsa_info.clone()
    }

    fn get_public_key(&self, sk: &[u8]) -> Result<Vec<u8>> {
        match self.dsa_info.dsa_type {
            PrehashDsaType::SlhDsaSha2_128f => get_public_key!(slh_dsa_sha2_128f, sk),
            PrehashDsaType::SlhDsaSha2_128s => get_public_key!(slh_dsa_sha2_128s, sk),
            PrehashDsaType::SlhDsaSha2_192f => get_public_key!(slh_dsa_sha2_192f, sk),
            PrehashDsaType::SlhDsaSha2_192s => get_public_key!(slh_dsa_sha2_192s, sk),
            PrehashDsaType::SlhDsaSha2_256f => get_public_key!(slh_dsa_sha2_256f, sk),
            PrehashDsaType::SlhDsaSha2_256s => get_public_key!(slh_dsa_sha2_256s, sk),
            PrehashDsaType::SlhDsaShake128f => get_public_key!(slh_dsa_shake_128f, sk),
            PrehashDsaType::SlhDsaShake128s => get_public_key!(slh_dsa_shake_128s, sk),
            PrehashDsaType::SlhDsaShake192f => get_public_key!(slh_dsa_shake_192f, sk),
            PrehashDsaType::SlhDsaShake192s => get_public_key!(slh_dsa_shake_192s, sk),
            PrehashDsaType::SlhDsaShake256f => get_public_key!(slh_dsa_shake_256f, sk),
            PrehashDsaType::SlhDsaShake256s => get_public_key!(slh_dsa_shake_256s, sk),
            _ => Err(QuantCryptError::NotImplemented),
        }
    }

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to sign
    /// * `sk` - The secret key
    /// * `ctx` - The context
    ///
    /// # Returns
    ///
    /// The signature
    fn sign_with_ctx(&self, sk: &[u8], msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>> {
        let ctx = ctx.unwrap_or(&[]);
        match self.dsa_info.dsa_type {
            PrehashDsaType::SlhDsaSha2_128s => sign_slh!(slh_dsa_sha2_128s, &sk, msg, ctx),
            PrehashDsaType::SlhDsaSha2_128f => sign_slh!(slh_dsa_sha2_128f, &sk, msg, ctx),
            PrehashDsaType::SlhDsaSha2_192s => sign_slh!(slh_dsa_sha2_192s, &sk, msg, ctx),
            PrehashDsaType::SlhDsaSha2_192f => sign_slh!(slh_dsa_sha2_192f, &sk, msg, ctx),
            PrehashDsaType::SlhDsaSha2_256s => sign_slh!(slh_dsa_sha2_256s, &sk, msg, ctx),
            PrehashDsaType::SlhDsaSha2_256f => sign_slh!(slh_dsa_sha2_256f, &sk, msg, ctx),
            PrehashDsaType::SlhDsaShake128s => sign_slh!(slh_dsa_shake_128s, &sk, msg, ctx),
            PrehashDsaType::SlhDsaShake128f => sign_slh!(slh_dsa_shake_128f, &sk, msg, ctx),
            PrehashDsaType::SlhDsaShake192s => sign_slh!(slh_dsa_shake_192s, &sk, msg, ctx),
            PrehashDsaType::SlhDsaShake192f => sign_slh!(slh_dsa_shake_192f, &sk, msg, ctx),
            PrehashDsaType::SlhDsaShake256s => sign_slh!(slh_dsa_shake_256s, &sk, msg, ctx),
            PrehashDsaType::SlhDsaShake256f => sign_slh!(slh_dsa_shake_256f, &sk, msg, ctx),
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
    /// * `ctx` - The context
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid
    fn verify_with_ctx(
        &self,
        pk: &[u8],
        msg: &[u8],
        signature: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<bool> {
        let ctx = ctx.unwrap_or(&[]);
        match self.dsa_info.dsa_type {
            PrehashDsaType::SlhDsaSha2_128f => {
                verify_slh!(slh_dsa_sha2_128f, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaSha2_128s => {
                verify_slh!(slh_dsa_sha2_128s, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaSha2_192f => {
                verify_slh!(slh_dsa_sha2_192f, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaSha2_192s => {
                verify_slh!(slh_dsa_sha2_192s, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaSha2_256f => {
                verify_slh!(slh_dsa_sha2_256f, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaSha2_256s => {
                verify_slh!(slh_dsa_sha2_256s, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaShake128f => {
                verify_slh!(slh_dsa_shake_128f, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaShake128s => {
                verify_slh!(slh_dsa_shake_128s, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaShake192f => {
                verify_slh!(slh_dsa_shake_192f, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaShake192s => {
                verify_slh!(slh_dsa_shake_192s, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaShake256f => {
                verify_slh!(slh_dsa_shake_256f, pk, msg, signature, ctx)
            }
            PrehashDsaType::SlhDsaShake256s => {
                verify_slh!(slh_dsa_shake_256s, pk, msg, signature, ctx)
            }
            _ => Err(QuantCryptError::NotImplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::Certificate;
    use crate::dsa::common::macros::test_dsa;

    #[test]
    fn test_slh_dsa_sha2_128s() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaSha2_128s);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-sha2-128s-2.16.840.1.101.3.4.3.20_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_sha2_128f() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaSha2_128f);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-sha2-128f-2.16.840.1.101.3.4.3.21_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_sha2_192s() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaSha2_192s);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-sha2-192s-2.16.840.1.101.3.4.3.22_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_sha2_192f() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaSha2_192f);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-sha2-192f-2.16.840.1.101.3.4.3.23_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_sha2_256s() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaSha2_256s);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-sha2-256s-2.16.840.1.101.3.4.3.24_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_sha2_256f() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaSha2_256f);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-sha2-256f-2.16.840.1.101.3.4.3.25_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_shake_128s() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaShake128s);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-shake-128s-2.16.840.1.101.3.4.3.26_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_shake_128f() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaShake128f);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-shake-128f-2.16.840.1.101.3.4.3.27_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_shake_192s() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaShake192s);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-shake-192s-2.16.840.1.101.3.4.3.28_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_shake_192f() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaShake192f);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-shake-192f-2.16.840.1.101.3.4.3.29_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_shake_256s() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaShake256s);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-shake-256s-2.16.840.1.101.3.4.3.30_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }

    #[test]
    fn test_slh_dsa_shake_256f() {
        let dsa = SlhDsaManager::new(PrehashDsaType::SlhDsaShake256f);
        test_dsa!(dsa);

        let cert_bytes =
            include_bytes!("../../test/data/slh/slh-dsa-shake-256f-2.16.840.1.101.3.4.3.31_ta.der");
        let cert = Certificate::from_der(cert_bytes).unwrap();
        assert!(cert.verify_self_signed().unwrap());
    }
}
