use crate::kem::kem_type::KemType;

use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// Key Encapsulation Mechanism (KEM) trait
pub trait Kem {
    /// Create a new KEM instance
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM to create
    /// * `seed` - A 32-byte seed
    fn new(kem_type: KemType) -> Self;

    /// Generate a keypair
    ///
    /// # Returns
    ///
    /// A tuple containing the public and secret keys (pk, sk)
    fn key_gen(&mut self, seed: Option<&[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Encapsulate a public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate
    ///
    /// # Returns
    ///
    /// A tuple containing the ciphertext and shared secret (ct, ss)
    fn encap(&mut self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a ciphertext
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to decapsulate with
    /// * `ct` - The ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The shared secret
    fn decap(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>>;

    /// Get the expected length of the shared secret in bytes
    ///
    /// # Returns
    ///
    /// The length of the shared secret in bytes
    fn get_ss_byte_len(&self) -> usize;

    /// Get the expected length of the ciphertext in bytes
    /// (for the encaps method)
    ///
    /// This may return `None` if the KEM doesn't have a fixed size for the ciphertext (ML KEMs).
    ///
    /// # Returns
    ///
    /// The length of the ciphertext in bytes
    fn get_ct_byte_len(&self) -> Option<usize>;

    /// Get the expected length of the public key in bytes
    ///
    /// This may return `None` if the KEM doesn't have a fixed size for the secret key (RSA KEMs).
    ///
    /// # Returns
    ///
    /// The length of the public key in bytes
    fn get_pk_byte_len(&self) -> Option<usize>;

    /// Get the expected length of the secret key in bytes.
    ///
    /// This may return `None` if the KEM doesn't have a fixed size for the secret key (RSA KEMs).
    ///
    /// # Returns
    ///
    /// The length of the secret key in bytes
    fn get_sk_byte_len(&self) -> Option<usize>;

    /// Get the type of KEM
    ///
    /// # Returns
    ///
    /// The type of KEM
    fn get_kem_type(&self) -> KemType;
}
