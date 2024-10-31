use crate::asn1::private_key::PrivateKey;
use crate::asn1::public_key::PublicKey;
use crate::dsa::common::config::oids::Oid;
use crate::dsa::common::prehash_dsa_trait::PrehashDsa;
use crate::dsa::{
    api::algorithm::DsaAlgorithm, common::dsa_trait::Dsa, dsa_manager::DsaManager,
    dsa_manager::PrehashDsaManager,
};
use crate::errors;

type Result<T> = std::result::Result<T, errors::QuantCryptError>;

/// A key generator for DSA keys
///
/// # Example
/// ```
/// use quantcrypt::dsas::DsaKeyGenerator;
/// use quantcrypt::dsas::DsaAlgorithm;
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
    /// Create a new `DsaKeyGenerator` with the specified algorithm
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
        if let Some(dsa_type) = self.algorithm.get_dsa_type() {
            let mut dsa_manager = DsaManager::new(dsa_type.clone())?;
            let (pk, sk) = dsa_manager.key_gen()?;
            let oid = dsa_type.get_oid();
            let pk = PublicKey::new(&oid, &pk)?;
            let sk = PrivateKey::new(&oid, &sk)?;
            Ok((pk, sk))
        } else {
            let dsa_type = self.algorithm.get_prehash_dsa_type().unwrap();
            let mut dsa_manager = PrehashDsaManager::new(dsa_type.clone())?;
            let (pk, sk) = dsa_manager.key_gen()?;
            let oid = dsa_type.get_oid();
            let pk = PublicKey::new(&oid, &pk)?;
            let sk = PrivateKey::new(&oid, &sk)?;
            Ok((pk, sk))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::dsas::{DsaAlgorithm, DsaKeyGenerator};

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
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(
            pk.get_oid(),
            DsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1.get_oid()
        );
        assert_eq!(
            sk.get_oid(),
            DsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1.get_oid()
        );
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm RSA PSS based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44Rsa2048Pss);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa44Rsa2048Pss.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa44Rsa2048Pss.get_oid());
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm RSA PKCS1 based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44Rsa2048Pkcs15);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa44Rsa2048Pkcs15.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa44Rsa2048Pkcs15.get_oid());
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm X25519 based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44Ed25519);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa44Ed25519.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa44Ed25519.get_oid());
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // Try a composite algorithm X448 based
        let mut key_generator = DsaKeyGenerator::new(DsaAlgorithm::MlDsa87Ed448);
        let (pk, sk) = key_generator.generate().unwrap();
        assert_eq!(pk.get_oid(), DsaAlgorithm::MlDsa87Ed448.get_oid());
        assert_eq!(sk.get_oid(), DsaAlgorithm::MlDsa87Ed448.get_oid());
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());
    }
}
