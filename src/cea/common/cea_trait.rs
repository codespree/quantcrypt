use crate::{cea::common::cea_type::CeaType, QuantCryptError};

use crate::cea::common::cea_info::CeaInfo;
use crate::cea::common::config::oids::Oid;

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Cea {
    /// Create a new Cea instance
    ///
    /// # Arguments
    ///
    /// * `kdf_type` - The type of KDF to create
    fn new(cea_type: CeaType) -> Result<Self>
    where
        Self: Sized;

    /// Generate a symmetric key using the default RNG
    ///
    /// # Returns
    ///
    /// The generated symmetric key
    fn key_gen(&mut self) -> Result<Vec<u8>>;

    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_cea_types = CeaType::all();
        for cae_type in all_cea_types {
            if cae_type.get_oid() == oid {
                let cae = Self::new(cae_type)?;
                return Ok(cae);
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
    /// * `plaintext` - The plaintext to encrypt
    /// * `aad` - The additional authenticated data to use
    /// * `content_type_oid` - The OID of the content type to use (optional), defaults to 1.2.840.113549.1.7.1.6
    ///
    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
        content_type_oid: Option<&str>,
    ) -> Result<Vec<u8>>;

    /// Decrypt a message and return the plaintext. The message should be in the
    /// format of a EncryptedContentInfo object as DER bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to use for decryption
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `aad` - The additional authenticated data to use
    ///
    /// # Returns
    ///
    /// The decrypted plaintext
    fn decrypt(key: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
}
