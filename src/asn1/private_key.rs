use der::{Decode, Encode};
use pem::EncodeConfig;
use pkcs8::spki::{self, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};
use pkcs8::ObjectIdentifier;
use pkcs8::{spki::AlgorithmIdentifier, PrivateKeyInfo};

use crate::asn1::asn_util::{is_composite_kem_or_dsa_oid, is_valid_kem_or_dsa_oid};
use crate::asn1::signature::DsaSignature;
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::dsa_manager::DsaManager;
use crate::kem::common::kem_trait::Kem;
use crate::kem::kem_manager::KemManager;
use crate::oid_mapper::map_to_new_oid;
use crate::{asn1::composite_private_key::CompositePrivateKey, errors};
use crate::{PublicKey, QuantCryptError};
use signature::{Keypair, Signer};

use crate::asn1::asn_util::is_dsa_oid;

type Result<T> = std::result::Result<T, QuantCryptError>;
/// A raw public key for use with the certificate builder
pub struct PrivateKey {
    /// The OID for the DSA / KEM
    oid: String,
    /// The key material
    private_key: Vec<u8>,
    /// Is it a composite key
    is_composite: bool,
    /// The public key.
    public_key: Option<PublicKey>,
}

impl Signer<DsaSignature> for PrivateKey {
    fn try_sign(&self, tbs: &[u8]) -> core::result::Result<DsaSignature, signature::Error> {
        let sm = self.sign(tbs).map_err(|_| signature::Error::new())?;
        Ok(DsaSignature(sm))
    }
}

impl Keypair for PrivateKey {
    type VerifyingKey = PublicKey;

    fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
        // TODO: This can panic if public key is not set
        self.public_key.clone().unwrap()
    }
}

impl DynSignatureAlgorithmIdentifier for PrivateKey {
    fn signature_algorithm_identifier(
        &self,
    ) -> core::result::Result<AlgorithmIdentifier<der::Any>, spki::Error> {
        let oid: ObjectIdentifier = self.oid.parse().map_err(|_| spki::Error::KeyMalformed)?;
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        };
        Ok(spki_algorithm)
    }
}

impl PrivateKey {
    /// Create a new private key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the DSA / KEM
    /// * `key` - The key material
    ///
    /// # Returns
    ///
    /// A new private key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPrivateKey` will be returned if the OID is invalid
    pub(crate) fn new(oid: &str, key: &[u8], public_key: Option<PublicKey>) -> Result<Self> {
        if !is_valid_kem_or_dsa_oid(&oid.to_string()) {
            return Err(errors::QuantCryptError::InvalidPrivateKey);
        }
        let is_composite = is_composite_kem_or_dsa_oid(oid);
        Ok(Self {
            oid: oid.to_string(),
            private_key: key.to_vec(),
            is_composite,
            public_key,
        })
    }

    /// Create a new private key from a composite private key
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key (if available)
    /// * `composite_sk` - The composite private key
    ///
    /// # Returns
    ///
    /// A new private key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPrivateKey` will be returned if the private key is invalid
    pub fn from_composite(
        public_key: Option<PublicKey>,
        composite_sk: &CompositePrivateKey,
    ) -> Result<Self> {
        Ok(Self {
            oid: composite_sk.get_oid().to_string(),
            private_key: composite_sk
                .to_der()
                .map_err(|_| errors::QuantCryptError::InvalidPrivateKey)?,
            is_composite: true,
            public_key,
        })
    }

    /// Get the OID for the DSA / KEM
    ///
    /// # Returns
    ///
    /// The OID for the DSA / KEM
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the key material
    ///
    /// # Returns
    ///
    /// The key material
    #[cfg(test)]
    fn get_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Get the public key
    ///
    /// # Returns
    ///
    /// The public key (if available)
    pub fn get_public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// Check if the key is a composite key
    ///
    /// # Returns
    ///
    /// True if the key is a composite key, false otherwise
    pub fn is_composite(&self) -> bool {
        self.is_composite
    }

    /// Get the key material as a DER-encoded byte array
    ///
    /// # Returns
    ///
    /// The DER-encoded byte array
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPrivateKey` will be returned if the private key is invalid
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let pub_key = self.public_key.as_ref().map(|pk| pk.get_key());

        let oid: ObjectIdentifier = self
            .oid
            .parse()
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;

        let priv_key_info = PrivateKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid,
                parameters: None,
            },
            private_key: &self.private_key,
            public_key: pub_key,
        };
        Ok(priv_key_info
            .to_der()
            .map_err(|_| errors::QuantCryptError::InvalidPrivateKey))?
    }

    /// Get the key material as a PEM-encoded string
    ///
    /// # Returns
    ///
    /// The PEM-encoded string
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPrivateKey` will be returned if the private key is invalid
    pub fn to_pem(&self) -> Result<String> {
        let der = self
            .to_der()
            .map_err(|_| errors::QuantCryptError::InvalidPrivateKey)?;
        let pem_obj = pem::Pem::new("PRIVATE KEY", der);
        let encode_conf = EncodeConfig::default().set_line_ending(pem::LineEnding::LF);
        Ok(pem::encode_config(&pem_obj, encode_conf))
    }

    /// Create a new private key from a PEM-encoded string
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM-encoded string
    ///
    /// # Returns
    ///
    /// A new private key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPrivateKey` will be returned if the private key is invalid
    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem::parse(pem).map_err(|_| errors::QuantCryptError::InvalidPrivateKey)?;
        // Header should be "PRIVATE KEY"
        if pem.tag() != "PRIVATE KEY" {
            return Err(errors::QuantCryptError::InvalidPrivateKey);
        }

        let der = pem.contents();
        Self::from_der(der)
    }

    /// Create a new private key from a DER-encoded byte array
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded byte array
    ///
    /// # Returns
    ///
    /// A new private key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPrivateKey` will be returned if the private key is invalid
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let priv_key_info = PrivateKeyInfo::from_der(der)
            .map_err(|_| errors::QuantCryptError::InvalidPrivateKey)?;

        let oid = map_to_new_oid(&priv_key_info.algorithm.oid.to_string());

        // Check if the OID is valid
        if !is_valid_kem_or_dsa_oid(&oid) {
            return Err(errors::QuantCryptError::InvalidPrivateKey);
        }

        // Check if the OID is a composite key
        let is_composite = is_composite_kem_or_dsa_oid(&oid);

        // Check if the public key is present
        let public_key = if let Some(pk) = priv_key_info.public_key {
            Some(PublicKey::new(&oid, pk)?)
        } else {
            None
        };

        Ok(Self {
            oid: oid.to_string(),
            private_key: priv_key_info.private_key.to_vec(),
            is_composite,
            public_key,
        })
    }

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign
    ///
    /// # Returns
    ///
    /// The signature
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Signing is only possible with DSA keys
        if !is_dsa_oid(&self.oid) {
            return Err(errors::QuantCryptError::UnsupportedOperation);
        }

        let dsa = DsaManager::new_from_oid(&self.oid)?;

        let sig = dsa.sign(&self.private_key, data)?;

        Ok(sig)
    }

    /// Use the private key to decapsulate a shared secret from a ciphertext
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext
    ///
    /// # Returns
    ///
    /// The shared secret
    ///
    /// # Errors
    ///
    /// `QuantCryptError::UnsupportedOperation` will be returned if this private key is not a KEM key
    pub(crate) fn decap(&self, ct: &[u8]) -> Result<Vec<u8>> {
        if is_dsa_oid(&self.oid) {
            return Err(errors::QuantCryptError::UnsupportedOperation);
        }
        let kem = KemManager::new_from_oid(&self.oid)?;
        let ss = kem.decap(&self.private_key, ct)?;
        Ok(ss)
    }

    /// Load a private key from a file. The file can be in either DER or PEM format
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    ///
    /// # Returns
    ///
    /// The private key
    pub fn from_file(path: &str) -> Result<Self> {
        // Read the contents of the file as bytes
        let contents = std::fs::read(path).map_err(|_| QuantCryptError::FileReadError)?;

        // Try to interpret as DER
        let result = PrivateKey::from_der(&contents);

        if let Ok(sk) = result {
            Ok(sk)
        } else {
            // Try to interpret as PEM
            let pem =
                std::str::from_utf8(&contents).map_err(|_| QuantCryptError::InvalidCertificate)?;
            if let Ok(sk) = PrivateKey::from_pem(pem) {
                Ok(sk)
            } else {
                Err(QuantCryptError::InvalidPrivateKey)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::dsa_type::DsaType;

    use super::*;

    #[test]
    fn test_composite_private_key() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_sk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem).unwrap();

        // There is no public key in the PEM file
        assert!(pk.public_key.is_none());

        assert!(pk.is_composite());
        assert_eq!(pk.get_oid(), DsaType::MlDsa44EcdsaP256SHA256.get_oid());

        let key_bytes = pk.get_key();
        let pk2 = CompositePrivateKey::from_der(&pk.oid, &key_bytes).unwrap();

        assert_eq!(pk.oid, pk2.get_oid());

        let pk2 = PrivateKey::from_composite(pk.public_key, &pk2).unwrap();
        let pem2 = pk2.to_pem().unwrap();
        assert_eq!(pem, pem2.trim());

        let oid = DsaType::MlDsa44EcdsaP256SHA256.get_oid();
        assert_eq!(pk.oid, oid);
    }

    #[test]
    fn test_pk_no_headers() {
        let pem_bytes = include_bytes!("../../test/data/bad/no_headers.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPrivateKey
        ));
    }

    #[test]
    fn test_pk_bad_base64() {
        let pem_bytes = include_bytes!("../../test/data/bad/bad_base64.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPrivateKey
        ));
    }

    #[test]
    fn test_pk_empty() {
        let pem_bytes = include_bytes!("../../test/data/bad/empty.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPrivateKey
        ));
    }

    #[test]
    fn test_pk_bad_tag() {
        let pem_bytes = include_bytes!("../../test/data/bad/bad_tag.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPrivateKey
        ));
    }

    #[test]
    fn test_pk_bad_algorithm() {
        let pem_bytes = include_bytes!("../../test/data/bad/private_rsa_2048.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPrivateKey
        ));
    }

    #[test]
    fn test_sk_serialization_deserialization() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_sk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PrivateKey::from_pem(pem).unwrap();

        let der = pk.to_der().unwrap();
        let pk2 = PrivateKey::from_der(&der).unwrap();
        let pem2 = pk2.to_pem().unwrap();
        assert_eq!(pem.trim(), pem2.trim());

        let der2 = pk2.to_der().unwrap();
        assert_eq!(der, der2);
    }

    #[test]
    fn test_sk_containing_pk() {
        let (pk, sk) = DsaManager::new(DsaType::MlDsa44)
            .unwrap()
            .key_gen()
            .unwrap();
        let pk = PublicKey::new(&DsaType::MlDsa44.get_oid(), &pk).unwrap();
        let sk = PrivateKey::new(&DsaType::MlDsa44.get_oid(), &sk, Some(pk.clone())).unwrap();
        let sk_der = sk.to_der().unwrap();
        let sk2 = PrivateKey::from_der(&sk_der).unwrap();
        let pk2 = sk2.get_public_key().unwrap();
        assert_eq!(pk.get_key(), pk2.get_key());
        assert_eq!(
            sk.get_public_key().unwrap().get_key(),
            sk2.get_public_key().unwrap().get_key()
        );
    }
}
