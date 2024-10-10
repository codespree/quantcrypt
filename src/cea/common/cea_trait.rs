// https://datatracker.ietf.org/doc/html/rfc5084#ref-CCM

use crate::{cea::common::cea_type::CeaType, QuantCryptError};

use crate::cea::common::cea_info::CeaInfo;
use crate::cea::common::config::oids::Oid;

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Cea {
    /// Create a new Cea instance
    ///
    /// # Arguments
    ///
    /// * `cea_type` - The type of CEA to create
    fn new(cea_type: CeaType) -> Result<Self>
    where
        Self: Sized;

    /// Generate a symmetric key using the default RNG
    ///
    /// # Returns
    ///
    /// The generated symmetric key
    fn key_gen(&mut self) -> Result<Vec<u8>>;

    /// Generate a nonce using the default RNG
    ///
    /// # Returns
    ///
    /// The generated nonce
    fn nonce_gen(&mut self) -> Result<Vec<u8>>;

    #[allow(dead_code)]
    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_cea_types = CeaType::all();
        for cea_type in all_cea_types {
            if cea_type.get_oid() == oid {
                let cea = Self::new(cea_type)?;
                return Ok(cea);
            }
        }
        Err(QuantCryptError::InvalidOid)
    }

    /// Get CEA metadata information such as OID
    ///
    /// # Returns
    ///
    /// A structure containing metadata about the CEA
    fn get_cea_info(&self) -> CeaInfo;

    /// Encrypt a message and return the DER bytes for a EncryptedContentInfo
    /// object.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to use for encryption
    /// * `nonce` - The nonce to use for encryption. If None, a random nonce will be generated
    /// * `plaintext` - The plaintext to encrypt
    /// * `aad` - The additional authenticated data to use
    /// * `content_type_oid` - The OID of the content type to use (optional), defaults to 1.2.840.113549.1.7.1.6
    ///
    /// # Returns
    ///
    /// A tuple containing the tag and the ciphertext (DER encoded bytes of a EncryptedContentInfo object)
    fn encrypt(
        &self,
        key: &[u8],
        nonce: Option<&[u8]>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        content_type_oid: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decrypt a message and return the plaintext. The message should be in the
    /// format of a EncryptedContentInfo object as DER bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to use for decryption
    /// * `tag` - The tag to use for decryption
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `aad` - The additional authenticated data to use
    ///
    /// # Returns
    ///
    /// The decrypted plaintext
    fn decrypt(key: &[u8], tag: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
}
