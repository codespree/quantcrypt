use crate::asn1::private_key::PrivateKey;
use crate::asn1::public_key::PublicKey;
use crate::dsa::common::config::oids::Oid;
use crate::dsa::{api::algorithm::DsaAlgorithm, common::dsa_trait::Dsa, dsa_manager::DsaManager};
use crate::errors;

type Result<T> = std::result::Result<T, errors::QuantCryptError>;

/// A key generator for DSA keys
///
/// # Example
/// ```
/// use quantcrypt::DsaKeyGenerator;
/// use quantcrypt::DsaAlgorithm;
///
/// let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44);
/// let (pk, sk) = key_generator.generate().unwrap();
///
/// let msg = b"Hello, world!";
///
/// let sig = sk.sign(msg).unwrap();
/// assert!(pk.verify(msg, &sig).unwrap());
/// ```
pub struct DsaKeyGenerator {
    /// The algorithm to use for key generation
    algorithm: DsaAlgorithm,
}

impl DsaKeyGenerator {
    /// Create a new `KeyGenerator` with the specified algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to use for key generation
    ///
    /// # Returns
    ///
    /// The new `KeyGenerator`
    pub fn new(algorithm: DsaAlgorithm) -> DsaKeyGenerator {
        DsaKeyGenerator { algorithm }
    }

    /// Generate a keypair using the default RNG
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    pub fn generate(&mut self) -> Result<(PublicKey, PrivateKey)> {
        let dsa_type = self.algorithm.get_dsa_type();
        let mut dsa_manager = DsaManager::new(dsa_type.clone())?;
        let (pk, sk) = dsa_manager.key_gen()?;
        let oid = dsa_type.get_oid();
        let pk = PublicKey::new(&oid, &pk)?;
        let sk = PrivateKey::new(&oid, &sk)?;
        Ok((pk, sk))
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::api::algorithm::DsaAlgorithm;
    use crate::dsa::api::key_generator::DsaKeyGenerator;

    #[test]
    fn test_key_generator_sign_verify() {
        // Try a pure algorithm
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa44.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa44.get_oid());

        let msg = b"Hello, world!";
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm EC based
        let mut key_generator =
            DsaKeyGenerator::new(DsaAlgorithm::MlDsa44EcdsaBrainpoolP256r1SHA256);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(
            pk.get_oid(),
            DsaAlgorithm::MlDsa44EcdsaBrainpoolP256r1SHA256.get_oid()
        );
        assert_eq!(
            sk.get_oid(),
            DsaAlgorithm::MlDsa44EcdsaBrainpoolP256r1SHA256.get_oid()
        );
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm RSA PSS based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44Rsa2048PssSha256);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(
            pk.get_oid(),
            DsaAlgorithm::MlDsa44Rsa2048PssSha256.get_oid()
        );
        assert_eq!(
            sk.get_oid(),
            DsaAlgorithm::MlDsa44Rsa2048PssSha256.get_oid()
        );
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm RSA PKCS1 based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44Rsa2048Pkcs15Sha256);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(
            pk.get_oid(),
            DsaAlgorithm::MlDsa44Rsa2048Pkcs15Sha256.get_oid()
        );
        assert_eq!(
            sk.get_oid(),
            DsaAlgorithm::MlDsa44Rsa2048Pkcs15Sha256.get_oid()
        );
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm X25519 based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44Ed25519SHA512);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa44Ed25519SHA512.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa44Ed25519SHA512.get_oid());
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm X448 based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa87Ed448SHA512);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa87Ed448SHA512.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa87Ed448SHA512.get_oid());
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());
    }
}
