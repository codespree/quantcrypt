use crate::asn1::asn_util::{is_composite_kem_or_dsa_oid, is_valid_kem_or_dsa_oid};
use crate::dsa::common::dsa_trait::Dsa;
use crate::dsa::common::prehash_dsa_trait::PrehashDsa;
use crate::dsa::common::prehash_dsa_type::PrehashDsaType;
use crate::dsa::dsa_manager::{DsaManager, PrehashDsaManager};
use crate::errors;
use crate::kem::common::kem_trait::Kem;
use crate::kem::kem_manager::KemManager;
use der::{asn1::BitString, Document};
use der::{Decode, Encode};
use pem::EncodeConfig;
use pkcs8::ObjectIdentifier;
use pkcs8::{spki::AlgorithmIdentifierWithOid, EncodePublicKey};

use crate::asn1::composite_public_key::CompositePublicKey;

use crate::asn1::public_key_info::PublicKeyInfo;

use super::asn_util::{is_dsa_oid, is_kem_oid};
use errors::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Clone)]
/// A raw public key for use with the certificate builder
pub struct PublicKey {
    /// The OID for the DSA / KEM
    oid: String,
    /// The key material
    key: Vec<u8>,
    /// Is it a composite key
    is_composite: bool,
}

impl PublicKey {
    /// Create a new public key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the DSA / KEM
    /// * `key` - The key material
    ///
    /// # Returns
    ///
    /// A new public key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPublicKey` will be returned if the OID is invalid
    /// or the key is invalid
    pub fn new(oid: &str, key: &[u8]) -> Result<Self> {
        if !is_valid_kem_or_dsa_oid(&oid.to_string()) {
            return Err(errors::QuantCryptError::InvalidPublicKey);
        }
        let is_composite = is_composite_kem_or_dsa_oid(oid);
        Ok(Self {
            oid: oid.to_string(),
            key: key.to_vec(),
            is_composite,
        })
    }

    /// Create a new public key from a composite public key
    ///
    /// # Arguments
    ///
    /// * `composite_pk` - The composite public key
    ///
    /// # Returns
    ///
    /// A new public key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPublicKey` will be returned if the public key is invalid
    pub fn from_composite(composite_pk: &CompositePublicKey) -> Result<Self> {
        Ok(Self {
            oid: composite_pk.get_oid().to_string(),
            key: composite_pk
                .to_der()
                .map_err(|_| errors::QuantCryptError::InvalidPublicKey)?,
            is_composite: true,
        })
    }

    /// Get the OID for the DSA / KEM public key algorithm
    ///
    /// # Returns
    ///
    /// The OID for the DSA / KEM public key algorithm
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the key material
    ///
    /// # Returns
    ///
    /// The key material
    pub fn get_key(&self) -> &[u8] {
        &self.key
    }

    /// Is it a composite key
    ///
    /// # Returns
    ///
    /// True if it is a composite key, false otherwise
    pub fn is_composite(&self) -> bool {
        self.is_composite
    }

    /// Convert the public key to a PEM-encoded string
    ///
    /// # Returns
    ///
    /// The PEM-encoded public key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPublicKey` will be returned if the public key is invalid
    pub fn to_pem(&self) -> Result<String> {
        let der = self
            .to_der()
            .map_err(|_| errors::QuantCryptError::InvalidPublicKey)?;
        let pem_obj = pem::Pem::new("PUBLIC KEY", der);
        let encode_conf = EncodeConfig::default().set_line_ending(pem::LineEnding::LF);
        Ok(pem::encode_config(&pem_obj, encode_conf))
    }

    /// Get's the raw public key as a BitString such that it can be used in a OneAsymmetricKey structure
    ///
    /// # Returns
    ///
    /// The public key as a BitString
    pub(crate) fn to_bitstring(&self) -> Result<BitString> {
        let pk_bs = BitString::from_bytes(&self.key)
            .map_err(|_| errors::QuantCryptError::InvalidPublicKey)?;
        Ok(pk_bs)
    }

    /// Convert the public key to a DER-encoded byte array. The raw public key is wrapped in a
    /// SubjectPublicKeyInfo structure.
    ///
    /// # Returns
    ///
    /// The DER-encoded byte array
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPublicKey` will be returned if the public key is invalid
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let pk_bs = self.to_bitstring()?;

        let oid: ObjectIdentifier = self
            .oid
            .parse()
            .map_err(|_| QuantCryptError::InvalidPublicKey)?;

        let pub_key_info = PublicKeyInfo {
            algorithm: AlgorithmIdentifierWithOid {
                oid,
                parameters: None,
            },
            public_key: pk_bs,
        };
        let der = pub_key_info
            .to_der()
            .map_err(|_| errors::QuantCryptError::InvalidPublicKey)?;
        Ok(der)
    }

    /// Create a new public key from a PEM-encoded string
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM-encoded public key
    ///
    /// # Returns
    ///
    /// A new public key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPublicKey` will be returned if the public key is invalid
    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem::parse(pem).map_err(|_| errors::QuantCryptError::InvalidPublicKey)?;
        // Header should be "PUBLIC KEY"
        if pem.tag() != "PUBLIC KEY" {
            return Err(errors::QuantCryptError::InvalidPublicKey);
        }

        let der = pem.contents();
        Self::from_der(der)
    }

    /// Create a new public key from a DER-encoded byte array
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded public key
    ///
    /// # Returns
    ///
    /// A new public key
    ///
    /// # Errors
    ///
    /// `KeyError::InvalidPublicKey` will be returned if the public key is invalid
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let pub_key_info =
            PublicKeyInfo::from_der(der).map_err(|_| errors::QuantCryptError::InvalidPublicKey)?;
        let pk_bytes = if let Some(pk_bytes) = pub_key_info.public_key.as_bytes() {
            pk_bytes
        } else {
            return Err(errors::QuantCryptError::InvalidPublicKey);
        };

        let oid = pub_key_info.algorithm.oid.to_string();

        // Check if oid is valid
        if !is_valid_kem_or_dsa_oid(&oid) {
            return Err(errors::QuantCryptError::InvalidPublicKey);
        }

        let is_composite = is_composite_kem_or_dsa_oid(&oid);

        Ok(Self {
            oid,
            key: pk_bytes.to_vec(),
            is_composite,
        })
    }

    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `message` - The message to verify
    /// * `signature` - The signature
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid
    ///
    /// # Errors
    ///
    /// `QuantCryptError::UnsupportedOperation` will be returned if the OID is not a DSA key
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Check if this is a DSA key
        if !is_dsa_oid(&self.oid) {
            return Err(errors::QuantCryptError::UnsupportedOperation);
        }

        let result = if let Some(dsa_type) = PrehashDsaType::from_oid(&self.oid) {
            let dsa_manager = PrehashDsaManager::new(dsa_type)?;
            dsa_manager
                .verify(self.get_key(), message, signature)
                .unwrap_or(false)
        } else {
            let dsa_manager = DsaManager::new_from_oid(&self.oid)?;
            dsa_manager
                .verify(self.get_key(), message, signature)
                .unwrap_or(false)
        };

        Ok(result)
    }

    /// Encapsulate to get a shared secret and a ciphertext based on this public key
    ///
    /// # Returns
    ///
    /// A tuple containing the ciphertext and the shared secret (ct, ss)
    pub fn encap(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Check if this is a KEM key
        if !is_kem_oid(&self.oid) {
            return Err(errors::QuantCryptError::UnsupportedOperation);
        }

        let mut kem =
            KemManager::new_from_oid(&self.oid).map_err(|_| errors::QuantCryptError::InvalidOid)?;

        let (ct, ss) = kem.encap(self.get_key())?;

        Ok((ct, ss))
    }

    /// Save the public key to a file in PEM format
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    ///
    /// # Errors
    ///
    /// `QuantCryptError::FileWriteError` will be returned if there is an error writing to the file
    pub fn to_pem_file(&self, path: &str) -> Result<()> {
        let pem = self
            .to_pem()
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        std::fs::write(path, pem).map_err(|_| QuantCryptError::FileWriteError)?;
        Ok(())
    }

    /// Save the public key to a file in DER format
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    ///
    /// # Errors
    ///
    /// `QuantCryptError::FileWriteError` will be returned if there is an error writing to the file
    /// `QuantCryptError::InvalidPublicKey` will be returned if the public key is invalid
    pub fn to_der_file(&self, path: &str) -> Result<()> {
        let der = self
            .to_der()
            .map_err(|_| QuantCryptError::InvalidPublicKey)?;
        std::fs::write(path, der).map_err(|_| QuantCryptError::FileWriteError)?;
        Ok(())
    }

    /// Load a public key from a file
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    ///
    /// # Returns
    ///
    /// A new public key
    pub fn from_file(path: &str) -> Result<Self> {
        // Read the contents of the file as bytes
        let contents = std::fs::read(path).map_err(|_| QuantCryptError::FileReadError)?;

        // Try to interpret as DER
        let result = PublicKey::from_der(&contents);

        if let Ok(sk) = result {
            Ok(sk)
        } else {
            // Try to interpret as PEM
            let pem =
                std::str::from_utf8(&contents).map_err(|_| QuantCryptError::InvalidCertificate)?;
            if let Ok(sk) = PublicKey::from_pem(pem) {
                Ok(sk)
            } else {
                Err(QuantCryptError::InvalidPrivateKey)
            }
        }
    }
}

impl EncodePublicKey for PublicKey {
    fn to_public_key_der(&self) -> std::result::Result<Document, pkcs8::spki::Error> {
        let der = self
            .to_der()
            .map_err(|_| pkcs8::spki::Error::KeyMalformed)?;
        let doc = Document::try_from(der)?;
        Ok(doc)
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::common::config::oids::Oid;
    use crate::dsa::common::prehash_dsa_type::PrehashDsaType;

    use super::*;

    #[test]
    fn test_composite_public_key() {
        let pem_bytes = include_bytes!("../../test/data/mldsa44_ecdsa_p256_sha256_pk.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PublicKey::from_pem(pem).unwrap();

        assert!(pk.is_composite());
        assert_eq!(
            pk.get_oid(),
            PrehashDsaType::HashMlDsa44EcdsaP256Sha256.get_oid()
        );

        let key_bytes = pk.get_key();
        let pk2 = CompositePublicKey::from_der(&pk.oid, &key_bytes).unwrap();

        assert_eq!(pk.oid, pk2.get_oid());

        let pk2 = PublicKey::from_composite(&pk2).unwrap();
        let pem2 = pk2.to_pem().unwrap();
        assert_eq!(pem, pem2.trim());

        let oid = PrehashDsaType::HashMlDsa44EcdsaP256Sha256.get_oid();
        assert_eq!(pk.oid, oid);
    }

    #[test]
    fn test_pk_no_headers() {
        let pem_bytes = include_bytes!("../../test/data/bad/no_headers.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PublicKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_pk_bad_base64() {
        let pem_bytes = include_bytes!("../../test/data/bad/bad_base64.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PublicKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_pk_empty() {
        let pem_bytes = include_bytes!("../../test/data/bad/empty.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PublicKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_pk_bad_tag() {
        let pem_bytes = include_bytes!("../../test/data/bad/bad_tag.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PublicKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_pk_bad_algorithm() {
        let pem_bytes = include_bytes!("../../test/data/bad/public_rsa_2048.pem");
        let pem = std::str::from_utf8(pem_bytes).unwrap().trim();
        let pk = PublicKey::from_pem(pem);

        assert!(pk.is_err());
        assert!(matches!(
            pk.err().unwrap(),
            errors::QuantCryptError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_pk_from_file() {
        let pk = PublicKey::from_file(
            "test/data/bc_artifacts_certs_r4/external_ml-kem-512-2.16.840.1.101.3.4.4.1_public.der",
        )
        .unwrap();
        pk.encap().unwrap();
    }
}
