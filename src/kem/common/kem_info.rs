use crate::kem::common::config::ct_len::CTLen;
use crate::kem::common::config::oids::Oid;
use crate::kem::common::config::pk_len::PKLen;
use crate::kem::common::config::sk_len::SKLen;
use crate::kem::common::config::ss_len::SSLen;
use crate::kem::common::kem_type::KemType;

/// A structure to represent metadata about a KEM
///
/// This is also used to test the correctness of the KEM
#[derive(Clone)]
#[allow(dead_code)]
pub struct KemInfo {
    /// The type of KEM
    pub kem_type: KemType,
    /// The length of the shared secret in bytes
    pub ss_byte_len: usize,
    /// The length of the public key in bytes (if fixed size, otherwise `None`)
    pub pk_byte_len: Option<usize>,
    /// The length of the secret key in bytes (if fixed size, otherwise `None`)
    pub sk_byte_len: Option<usize>,
    /// The length of the ciphertext in bytes (if fixed size, otherwise `None`)
    pub ct_byte_len: Option<usize>,
    /// The OID of the KEM
    pub oid: String,
}

impl KemInfo {
    /// Create a new `KemInfo` structure
    ///
    /// # Arguments
    ///
    /// * `kem_type` - The type of KEM
    pub fn new(kem_type: KemType) -> KemInfo {
        KemInfo {
            kem_type: kem_type.clone(),
            ss_byte_len: kem_type.get_ss_len(),
            pk_byte_len: kem_type.get_pk_len(),
            sk_byte_len: kem_type.get_sk_len(),
            ct_byte_len: kem_type.get_ct_len(),
            oid: kem_type.get_oid(),
        }
    }
}
